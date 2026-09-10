use crate::proxy::monitor::ProxyRequestLog;
use rusqlite::{params, Connection};
use std::path::PathBuf;

pub fn get_proxy_db_path() -> Result<PathBuf, String> {
    let data_dir = crate::modules::account::get_data_dir()?;
    Ok(data_dir.join("proxy_logs.db"))
}

fn connect_db() -> Result<Connection, String> {
    let db_path = get_proxy_db_path()?;
    let conn = Connection::open(db_path).map_err(|e| e.to_string())?;

    // Enable WAL mode for better concurrency
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(|e| e.to_string())?;

    // Set busy timeout to 5000ms to avoid "database is locked" errors
    conn.pragma_update(None, "busy_timeout", 5000)
        .map_err(|e| e.to_string())?;

    // Synchronous NORMAL is faster and safe enough for WAL
    conn.pragma_update(None, "synchronous", "NORMAL")
        .map_err(|e| e.to_string())?;

    // Enable incremental vacuum mode for gradual space reclamation
    let _ = conn.pragma_update(None, "auto_vacuum", "INCREMENTAL");

    Ok(conn)
}

pub fn init_db() -> Result<(), String> {
    // connect_db will initialize WAL mode and other pragmas
    let conn = connect_db()?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS request_logs (
            id TEXT PRIMARY KEY,
            timestamp INTEGER,
            method TEXT,
            url TEXT,
            status INTEGER,
            duration INTEGER,
            model TEXT,
            error TEXT
        )",
        [],
    )
    .map_err(|e| e.to_string())?;

    // Try to add new columns (ignore errors if they exist)
    let _ = conn.execute("ALTER TABLE request_logs ADD COLUMN request_body TEXT", []);
    let _ = conn.execute("ALTER TABLE request_logs ADD COLUMN response_body TEXT", []);
    let _ = conn.execute(
        "ALTER TABLE request_logs ADD COLUMN input_tokens INTEGER",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE request_logs ADD COLUMN output_tokens INTEGER",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE request_logs ADD COLUMN cached_tokens INTEGER",
        [],
    );
    let _ = conn.execute("ALTER TABLE request_logs ADD COLUMN account_email TEXT", []);
    let _ = conn.execute("ALTER TABLE request_logs ADD COLUMN mapped_model TEXT", []);
    let _ = conn.execute("ALTER TABLE request_logs ADD COLUMN protocol TEXT", []);
    let _ = conn.execute("ALTER TABLE request_logs ADD COLUMN client_ip TEXT", []);
    let _ = conn.execute("ALTER TABLE request_logs ADD COLUMN username TEXT", []);

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_timestamp ON request_logs (timestamp DESC)",
        [],
    )
    .map_err(|e| e.to_string())?;

    // Add status index for faster stats queries
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_status ON request_logs (status)",
        [],
    )
    .map_err(|e| e.to_string())?;

    Ok(())
}

/// Maximum stored body size in database (64 KB) to prevent log database explosion
pub const MAX_STORED_BODY_BYTES: usize = 64 * 1024;

/// Sanitize large inline media (base64 data) from request/response body before storage
pub fn sanitize_body_inline_media(body: &str) -> String {
    if (body.starts_with('{') || body.starts_with('['))
        && (body.contains("data:image/")
            || body.contains("data:audio/")
            || body.contains("\"inlineData\"")
            || body.contains("\"inline_data\""))
    {
        if let Ok(mut val) = serde_json::from_str::<serde_json::Value>(body) {
            strip_json_inline_media(&mut val);
            if let Ok(serialized) = serde_json::to_string(&val) {
                return serialized;
            }
        }
    }

    if body.contains("data:image/") || body.contains("data:audio/") {
        if let Ok(re) = regex::Regex::new(
            r#"data:(image|audio|video)/[a-zA-Z0-9.+_-]+;base64,[A-Za-z0-9+/=]{100,}"#,
        ) {
            return re.replace_all(body, "[inline media omitted]").into_owned();
        }
    }

    body.to_string()
}

fn strip_json_inline_media(val: &mut serde_json::Value) {
    match val {
        serde_json::Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if (k == "data" || k == "inlineData" || k == "inline_data") && v.is_string() {
                    let len = v.as_str().map(|s| s.len()).unwrap_or(0);
                    if len > 200 {
                        *v = serde_json::Value::String(format!(
                            "[inline data omitted: {} chars]",
                            len
                        ));
                    }
                } else if k == "url" && v.is_string() {
                    if let Some(s) = v.as_str() {
                        if s.starts_with("data:image/") || s.starts_with("data:audio/") {
                            *v = serde_json::Value::String(format!(
                                "[data url omitted: {} chars]",
                                s.len()
                            ));
                        }
                    }
                } else {
                    strip_json_inline_media(v);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr.iter_mut() {
                strip_json_inline_media(item);
            }
        }
        serde_json::Value::String(s) => {
            if (s.starts_with("data:image/") || s.starts_with("data:audio/")) && s.len() > 200 {
                *s = format!("[data url omitted: {} chars]", s.len());
            }
        }
        _ => {}
    }
}

/// Truncate large request or response body safely before persisting to SQLite
pub fn truncate_body_for_storage(body: Option<&str>) -> Option<String> {
    let body = body?;
    let sanitized = sanitize_body_inline_media(body);
    if sanitized.len() <= MAX_STORED_BODY_BYTES {
        Some(sanitized)
    } else {
        // Safe UTF-8 character boundary truncation
        let mut end = MAX_STORED_BODY_BYTES;
        while end > 0 && !sanitized.is_char_boundary(end) {
            end -= 1;
        }
        let truncated = &sanitized[..end];
        Some(format!(
            "{}\n... [truncated: showing first {} bytes of {} bytes]",
            truncated,
            end,
            sanitized.len()
        ))
    }
}

pub fn save_log(log: &ProxyRequestLog) -> Result<(), String> {
    let conn = connect_db()?;

    let req_body = truncate_body_for_storage(log.request_body.as_deref());
    let resp_body = truncate_body_for_storage(log.response_body.as_deref());

    conn.execute(
        "INSERT INTO request_logs (id, timestamp, method, url, status, duration, model, error, request_body, response_body, input_tokens, output_tokens, cached_tokens, account_email, mapped_model, protocol, client_ip, username)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
        params![
            log.id,
            log.timestamp,
            log.method,
            log.url,
            log.status,
            log.duration,
            log.model,
            log.error,
            req_body,
            resp_body,
            log.input_tokens,
            log.output_tokens,
            log.cached_tokens,
            log.account_email,
            log.mapped_model,
            log.protocol,
            log.client_ip,
            log.username,
        ],
    ).map_err(|e| e.to_string())?;

    Ok(())
}

/// Get logs summary (without large request_body and response_body fields) with pagination
pub fn get_logs_summary(limit: usize, offset: usize) -> Result<Vec<ProxyRequestLog>, String> {
    let conn = connect_db()?;

    let mut stmt = conn
        .prepare(
            "SELECT id, timestamp, method, url, status, duration, model, error,
                NULL as request_body, NULL as response_body,
                input_tokens, output_tokens, cached_tokens, account_email, mapped_model, protocol, client_ip, username
         FROM request_logs 
         ORDER BY timestamp DESC 
         LIMIT ?1 OFFSET ?2",
        )
        .map_err(|e| e.to_string())?;

    let logs_iter = stmt
        .query_map([limit, offset], |row| {
            Ok(ProxyRequestLog {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                method: row.get(2)?,
                url: row.get(3)?,
                status: row.get(4)?,
                duration: row.get(5)?,
                model: row.get(6)?,
                error: row.get(7)?,
                request_body: None,  // Don't query large fields for list view
                response_body: None, // Don't query large fields for list view
                input_tokens: row.get(10).unwrap_or(None),
                output_tokens: row.get(11).unwrap_or(None),
                cached_tokens: row.get(12).unwrap_or(None),
                account_email: row.get(13).unwrap_or(None),
                mapped_model: row.get(14).unwrap_or(None),
                protocol: row.get(15).unwrap_or(None),
                client_ip: row.get(16).unwrap_or(None),
                username: row.get(17).unwrap_or(None),
            })
        })
        .map_err(|e| e.to_string())?;

    let mut logs = Vec::new();
    for log in logs_iter {
        logs.push(log.map_err(|e| e.to_string())?);
    }
    Ok(logs)
}

/// Get logs (backward compatible, calls get_logs_summary)
pub fn get_logs(limit: usize) -> Result<Vec<ProxyRequestLog>, String> {
    get_logs_summary(limit, 0)
}

pub fn get_stats() -> Result<crate::proxy::monitor::ProxyStats, String> {
    let conn = connect_db()?;

    // Optimized: Use single query instead of three separate queries
    // Use COALESCE to handle NULL values when table is empty (SUM returns NULL for empty set)
    let (total_requests, success_count, error_count): (u64, u64, u64) = conn
        .query_row(
            "SELECT
            COUNT(*) as total,
            COALESCE(SUM(CASE WHEN status >= 200 AND status < 400 THEN 1 ELSE 0 END), 0) as success,
            COALESCE(SUM(CASE WHEN status < 200 OR status >= 400 THEN 1 ELSE 0 END), 0) as error
         FROM request_logs",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|e| e.to_string())?;

    Ok(crate::proxy::monitor::ProxyStats {
        total_requests,
        success_count,
        error_count,
    })
}

/// Get single log detail (with request_body and response_body)
pub fn get_log_detail(log_id: &str) -> Result<ProxyRequestLog, String> {
    let conn = connect_db()?;

    let mut stmt = conn
        .prepare(
            "SELECT id, timestamp, method, url, status, duration, model, error,
                request_body, response_body, input_tokens, output_tokens,
                cached_tokens, account_email, mapped_model, protocol, client_ip, username
         FROM request_logs
         WHERE id = ?1",
        )
        .map_err(|e| e.to_string())?;

    stmt.query_row([log_id], |row| {
        Ok(ProxyRequestLog {
            id: row.get(0)?,
            timestamp: row.get(1)?,
            method: row.get(2)?,
            url: row.get(3)?,
            status: row.get(4)?,
            duration: row.get(5)?,
            model: row.get(6)?,
            error: row.get(7)?,
            request_body: row.get(8).unwrap_or(None),
            response_body: row.get(9).unwrap_or(None),
            input_tokens: row.get(10).unwrap_or(None),
            output_tokens: row.get(11).unwrap_or(None),
            cached_tokens: row.get(12).unwrap_or(None),
            account_email: row.get(13).unwrap_or(None),
            mapped_model: row.get(14).unwrap_or(None),
            protocol: row.get(15).unwrap_or(None),
            client_ip: row.get(16).unwrap_or(None),
            username: row.get(17).unwrap_or(None),
        })
    })
    .map_err(|e| e.to_string())
}

/// Cleanup old logs (keep last N days)
pub fn cleanup_old_logs(days: i64) -> Result<usize, String> {
    let conn = connect_db()?;

    // Note: Request log timestamp is stored in milliseconds (chrono::Utc::now().timestamp_millis())
    let cutoff_timestamp_ms = chrono::Utc::now().timestamp_millis() - (days * 24 * 3600 * 1000);

    let deleted = conn
        .execute(
            "DELETE FROM request_logs WHERE timestamp < ?1",
            [cutoff_timestamp_ms],
        )
        .map_err(|e| e.to_string())?;

    if deleted > 0 {
        // Reclaim WAL space passively and run incremental vacuum without full blocking rewrite
        let _ = conn.execute("PRAGMA wal_checkpoint(PASSIVE)", []);
        let _ = conn.execute("PRAGMA incremental_vacuum(500)", []);
    }

    Ok(deleted)
}

/// Limit maximum log count (keep newest N records)
pub fn limit_max_logs(max_count: usize) -> Result<usize, String> {
    let conn = connect_db()?;

    let deleted = conn
        .execute(
            "DELETE FROM request_logs WHERE id NOT IN (
            SELECT id FROM request_logs ORDER BY timestamp DESC LIMIT ?1
        )",
            [max_count],
        )
        .map_err(|e| e.to_string())?;

    if deleted > 0 {
        let _ = conn.execute("PRAGMA wal_checkpoint(PASSIVE)", []);
        let _ = conn.execute("PRAGMA incremental_vacuum(500)", []);
    }

    Ok(deleted)
}

/// Maximum database size in bytes (100 MB). When exceeded, prune oldest records.
pub const MAX_DB_SIZE_BYTES: u64 = 100 * 1024 * 1024;
pub const TARGET_DB_SIZE_BYTES: u64 = 50 * 1024 * 1024;

/// Cleanup log database if its file size on disk exceeds limit
pub fn cleanup_database_size(max_bytes: u64, _target_bytes: u64) -> Result<usize, String> {
    let db_path = get_proxy_db_path()?;
    if !db_path.exists() {
        return Ok(0);
    }

    let file_size = std::fs::metadata(&db_path).map(|m| m.len()).unwrap_or(0);

    let wal_path = db_path.with_extension("db-wal");
    let wal_size = if wal_path.exists() {
        std::fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0)
    } else {
        0
    };

    let total_size = file_size + wal_size;
    if total_size <= max_bytes {
        return Ok(0);
    }

    tracing::warn!(
        "Proxy log database size ({} MB) exceeds limit ({} MB), pruning oldest records...",
        total_size / 1024 / 1024,
        max_bytes / 1024 / 1024
    );

    let conn = connect_db()?;
    let total_rows: u64 = conn
        .query_row("SELECT COUNT(*) FROM request_logs", [], |row| row.get(0))
        .unwrap_or(0);

    if total_rows == 0 {
        let _ = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)", []);
        let _ = conn.execute("VACUUM", []);
        return Ok(0);
    }

    // Keep the most recent 50% of rows (at least 100)
    let rows_to_keep = (total_rows / 2).max(100);
    let deleted = conn
        .execute(
            "DELETE FROM request_logs WHERE id NOT IN (
                SELECT id FROM request_logs ORDER BY timestamp DESC LIMIT ?1
            )",
            [rows_to_keep],
        )
        .map_err(|e| e.to_string())?;

    if deleted > 0 {
        let _ = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)", []);
        if let Err(e) = conn.execute("VACUUM", []) {
            tracing::warn!("VACUUM after database size cleanup failed: {}", e);
        }
        tracing::info!(
            "Pruned {} old log records and compacted proxy DB to stay under size limit",
            deleted
        );
    }

    Ok(deleted)
}

/// Comprehensive log maintenance: clean up expired logs by age, cap max rows, and checkpoint WAL
pub fn maintain_proxy_logs(
    days_to_keep: i64,
    max_records: usize,
) -> Result<(usize, usize), String> {
    let deleted_old = cleanup_old_logs(days_to_keep)?;
    let deleted_excess = limit_max_logs(max_records)?;
    let _ = cleanup_database_size(MAX_DB_SIZE_BYTES, TARGET_DB_SIZE_BYTES);
    Ok((deleted_old, deleted_excess))
}

pub fn clear_logs() -> Result<(), String> {
    let conn = connect_db()?;
    conn.execute("DELETE FROM request_logs", [])
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Get total count of logs in database
pub fn get_logs_count() -> Result<u64, String> {
    let conn = connect_db()?;

    let count: u64 = conn
        .query_row("SELECT COUNT(*) FROM request_logs", [], |row| row.get(0))
        .map_err(|e| e.to_string())?;

    Ok(count)
}

/// Get count of logs matching search filter
/// filter: search text to match in url, method, model, or status
/// errors_only: if true, only count logs with status < 200 or >= 400
pub fn get_logs_count_filtered(filter: &str, errors_only: bool) -> Result<u64, String> {
    let conn = connect_db()?;

    let filter_pattern = format!("%{}%", filter);

    let sql = if errors_only {
        "SELECT COUNT(*) FROM request_logs WHERE (status < 200 OR status >= 400)"
    } else if filter.is_empty() {
        "SELECT COUNT(*) FROM request_logs"
    } else {
        "SELECT COUNT(*) FROM request_logs WHERE
            (url LIKE ?1 OR method LIKE ?1 OR model LIKE ?1 OR CAST(status AS TEXT) LIKE ?1 OR account_email LIKE ?1)"
    };

    let count: u64 = if filter.is_empty() && !errors_only {
        conn.query_row(sql, [], |row| row.get(0))
    } else if errors_only {
        conn.query_row(sql, [], |row| row.get(0))
    } else {
        conn.query_row(sql, [&filter_pattern], |row| row.get(0))
    }
    .map_err(|e| e.to_string())?;

    Ok(count)
}

/// Get logs with search filter and pagination
/// filter: search text to match in url, method, model, or status
/// errors_only: if true, only return logs with status < 200 or >= 400
pub fn get_logs_filtered(
    filter: &str,
    errors_only: bool,
    limit: usize,
    offset: usize,
) -> Result<Vec<ProxyRequestLog>, String> {
    let conn = connect_db()?;

    let filter_pattern = format!("%{}%", filter);

    let sql = if errors_only {
        "SELECT id, timestamp, method, url, status, duration, model, error,
                NULL as request_body, NULL as response_body,
                input_tokens, output_tokens, cached_tokens, account_email, mapped_model, protocol, client_ip, username
         FROM request_logs
         WHERE (status < 200 OR status >= 400)
         ORDER BY timestamp DESC
         LIMIT ?1 OFFSET ?2"
    } else if filter.is_empty() {
        "SELECT id, timestamp, method, url, status, duration, model, error,
                NULL as request_body, NULL as response_body,
                input_tokens, output_tokens, cached_tokens, account_email, mapped_model, protocol, client_ip, username
         FROM request_logs
         ORDER BY timestamp DESC
         LIMIT ?1 OFFSET ?2"
    } else {
        "SELECT id, timestamp, method, url, status, duration, model, error,
                NULL as request_body, NULL as response_body,
                input_tokens, output_tokens, cached_tokens, account_email, mapped_model, protocol, client_ip, username
         FROM request_logs
         WHERE (url LIKE ?3 OR method LIKE ?3 OR model LIKE ?3 OR CAST(status AS TEXT) LIKE ?3 OR account_email LIKE ?3 OR client_ip LIKE ?3)
         ORDER BY timestamp DESC
         LIMIT ?1 OFFSET ?2"
    };

    let logs: Vec<ProxyRequestLog> = if filter.is_empty() && !errors_only {
        let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
        let logs_iter = stmt
            .query_map([limit, offset], |row| {
                Ok(ProxyRequestLog {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    method: row.get(2)?,
                    url: row.get(3)?,
                    status: row.get(4)?,
                    duration: row.get(5)?,
                    model: row.get(6)?,
                    error: row.get(7)?,
                    request_body: None,
                    response_body: None,
                    input_tokens: row.get(10).unwrap_or(None),
                    output_tokens: row.get(11).unwrap_or(None),
                    cached_tokens: row.get(12).unwrap_or(None),
                    account_email: row.get(13).unwrap_or(None),
                    mapped_model: row.get(14).unwrap_or(None),
                    protocol: row.get(15).unwrap_or(None),
                    client_ip: row.get(16).unwrap_or(None),
                    username: row.get(17).unwrap_or(None),
                })
            })
            .map_err(|e| e.to_string())?;
        logs_iter.filter_map(|r| r.ok()).collect()
    } else if errors_only {
        let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
        let logs_iter = stmt
            .query_map([limit, offset], |row| {
                Ok(ProxyRequestLog {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    method: row.get(2)?,
                    url: row.get(3)?,
                    status: row.get(4)?,
                    duration: row.get(5)?,
                    model: row.get(6)?,
                    error: row.get(7)?,
                    request_body: None,
                    response_body: None,
                    input_tokens: row.get(10).unwrap_or(None),
                    output_tokens: row.get(11).unwrap_or(None),
                    cached_tokens: row.get(12).unwrap_or(None),
                    account_email: row.get(13).unwrap_or(None),
                    mapped_model: row.get(14).unwrap_or(None),
                    protocol: row.get(15).unwrap_or(None),
                    client_ip: row.get(16).unwrap_or(None),
                    username: row.get(17).unwrap_or(None),
                })
            })
            .map_err(|e| e.to_string())?;
        logs_iter.filter_map(|r| r.ok()).collect()
    } else {
        let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
        let logs_iter = stmt
            .query_map(rusqlite::params![limit, offset, filter_pattern], |row| {
                Ok(ProxyRequestLog {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    method: row.get(2)?,
                    url: row.get(3)?,
                    status: row.get(4)?,
                    duration: row.get(5)?,
                    model: row.get(6)?,
                    error: row.get(7)?,
                    request_body: None,
                    response_body: None,
                    input_tokens: row.get(10).unwrap_or(None),
                    output_tokens: row.get(11).unwrap_or(None),
                    cached_tokens: row.get(12).unwrap_or(None),
                    account_email: row.get(13).unwrap_or(None),
                    mapped_model: row.get(14).unwrap_or(None),
                    protocol: row.get(15).unwrap_or(None),
                    client_ip: row.get(16).unwrap_or(None),
                    username: row.get(17).unwrap_or(None),
                })
            })
            .map_err(|e| e.to_string())?;
        logs_iter.filter_map(|r| r.ok()).collect()
    };

    Ok(logs)
}

/// Get all logs with full details for export
pub fn get_all_logs_for_export() -> Result<Vec<ProxyRequestLog>, String> {
    let conn = connect_db()?;

    let mut stmt = conn
        .prepare(
            "SELECT id, timestamp, method, url, status, duration, model, error,
                request_body, response_body, input_tokens, output_tokens,
                cached_tokens, account_email, mapped_model, protocol, client_ip, username
         FROM request_logs
         ORDER BY timestamp DESC",
        )
        .map_err(|e| e.to_string())?;

    let logs_iter = stmt
        .query_map([], |row| {
            Ok(ProxyRequestLog {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                method: row.get(2)?,
                url: row.get(3)?,
                status: row.get(4)?,
                duration: row.get(5)?,
                model: row.get(6)?,
                error: row.get(7)?,
                request_body: row.get(8).unwrap_or(None),
                response_body: row.get(9).unwrap_or(None),
                input_tokens: row.get(10).unwrap_or(None),
                output_tokens: row.get(11).unwrap_or(None),
                cached_tokens: row.get(12).unwrap_or(None),
                account_email: row.get(13).unwrap_or(None),
                mapped_model: row.get(14).unwrap_or(None),
                protocol: row.get(15).unwrap_or(None),
                client_ip: row.get(16).unwrap_or(None),
                username: row.get(17).unwrap_or(None),
            })
        })
        .map_err(|e| e.to_string())?;

    let mut logs = Vec::new();
    for log in logs_iter {
        logs.push(log.map_err(|e| e.to_string())?);
    }
    Ok(logs)
}

// ... existing code ...

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IpTokenStats {
    pub client_ip: String,
    pub total_tokens: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub request_count: i64,
    pub username: Option<String>,
}

/// Get token usage grouped by IP
pub fn get_token_usage_by_ip(limit: usize, hours: i64) -> Result<Vec<IpTokenStats>, String> {
    let conn = connect_db()?;

    // Fix: Database stores timestamp in milliseconds, but we were calculating 'since' in seconds
    // Convert 'hours' to milliseconds
    let since = chrono::Utc::now().timestamp_millis() - (hours * 3600 * 1000);

    // [FIX] 不再从 request_logs 表获取 username，因为该字段可能为空
    // 先获取 IP 统计数据，然后再单独查询每个 IP 的用户名
    let mut stmt = conn
        .prepare(
            "SELECT
            client_ip,
            COALESCE(SUM(input_tokens), 0) + COALESCE(SUM(output_tokens), 0) as total,
            COALESCE(SUM(input_tokens), 0) as input,
            COALESCE(SUM(output_tokens), 0) as output,
            COUNT(*) as cnt
         FROM request_logs
         WHERE timestamp >= ?1 AND client_ip IS NOT NULL AND client_ip != ''
         GROUP BY client_ip
         ORDER BY total DESC
         LIMIT ?2",
        )
        .map_err(|e| e.to_string())?;

    let rows = stmt
        .query_map(params![since, limit], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })
        .map_err(|e| e.to_string())?;

    let mut stats = Vec::new();
    for row in rows {
        let (client_ip, total_tokens, input_tokens, output_tokens, request_count) =
            row.map_err(|e| e.to_string())?;

        // 从 user_token_db 获取该 IP 关联的用户名
        // 这比从 request_logs 获取更可靠，因为 token_ip_bindings 表在每次 User Token 使用时都会更新
        let username =
            crate::modules::user_token_db::get_username_for_ip(&client_ip).unwrap_or(None);

        stats.push(IpTokenStats {
            client_ip,
            total_tokens,
            input_tokens,
            output_tokens,
            request_count,
            username,
        });
    }

    Ok(stats)
}
