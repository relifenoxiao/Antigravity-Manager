//! 测试 determine_retry_strategy 和 should_rotate_account 的所有分支，
//! 重点覆盖 404 重试与账号轮换逻辑。

use crate::proxy::handlers::common::{
    determine_retry_strategy, determine_retry_strategy_with_grace, should_rotate_account,
    RequestRetryState, RetryStrategy,
};
use std::time::Duration;

// ===== determine_retry_strategy =====

#[test]
fn test_retry_strategy_404() {
    let strategy = determine_retry_strategy(404, "", false);
    match strategy {
        RetryStrategy::FixedDelay(d) => assert_eq!(d, Duration::from_millis(300)),
        other => panic!("Expected FixedDelay(300ms), got {:?}", other),
    }
}

#[test]
fn test_retry_strategy_429_no_delay() {
    let strategy = determine_retry_strategy(429, "rate limited", false);
    assert!(
        matches!(strategy, RetryStrategy::LinearBackoff { base_ms: 5000 }),
        "Expected LinearBackoff {{ base_ms: 5000 }}, got {:?}",
        strategy
    );
}

#[test]
fn test_retry_strategy_503() {
    let strategy = determine_retry_strategy(503, "", false);
    assert!(
        matches!(
            strategy,
            RetryStrategy::ExponentialBackoff {
                base_ms: 10000,
                max_ms: 60000
            }
        ),
        "Expected ExponentialBackoff {{ base_ms: 10000, max_ms: 60000 }}, got {:?}",
        strategy
    );
}

#[test]
fn test_retry_strategy_529() {
    let strategy = determine_retry_strategy(529, "", false);
    assert!(
        matches!(
            strategy,
            RetryStrategy::ExponentialBackoff {
                base_ms: 10000,
                max_ms: 60000
            }
        ),
        "Expected ExponentialBackoff {{ base_ms: 10000, max_ms: 60000 }}, got {:?}",
        strategy
    );
}

#[test]
fn test_retry_strategy_500() {
    let strategy = determine_retry_strategy(500, "", false);
    assert!(
        matches!(strategy, RetryStrategy::LinearBackoff { base_ms: 3000 }),
        "Expected LinearBackoff {{ base_ms: 3000 }}, got {:?}",
        strategy
    );
}

#[test]
fn test_retry_strategy_401_403() {
    for status in [401, 403] {
        let strategy = determine_retry_strategy(status, "", false);
        match strategy {
            RetryStrategy::FixedDelay(d) => assert_eq!(d, Duration::from_millis(200)),
            other => panic!("Expected FixedDelay(200ms) for {}, got {:?}", status, other),
        }
    }
}

#[test]
fn test_retry_strategy_other() {
    for status in [200, 201, 301, 418, 502] {
        let strategy = determine_retry_strategy(status, "", false);
        assert!(
            matches!(strategy, RetryStrategy::NoRetry),
            "Expected NoRetry for {}, got {:?}",
            status,
            strategy
        );
    }
}

#[test]
fn test_retry_strategy_400_thinking_signature() {
    let signatures = [
        "Invalid `signature` for thinking",
        "Error with thinking.signature",
        "thinking.thinking block failed",
        "Corrupted thought signature detected",
    ];
    for sig in signatures {
        let strategy = determine_retry_strategy(400, sig, false);
        match strategy {
            RetryStrategy::FixedDelay(d) => assert_eq!(d, Duration::from_millis(200)),
            other => panic!(
                "Expected FixedDelay(200ms) for 400 + '{}', got {:?}",
                sig, other
            ),
        }
    }
}

#[test]
fn test_retry_strategy_400_no_signature() {
    let strategy = determine_retry_strategy(400, "bad request", false);
    assert!(
        matches!(strategy, RetryStrategy::NoRetry),
        "Expected NoRetry for 400 without signature, got {:?}",
        strategy
    );
}

// ===== should_rotate_account =====

#[test]
fn test_rotate_account_true_cases() {
    for status in [429, 401, 403, 404, 500] {
        assert!(
            should_rotate_account(status, None),
            "Expected should_rotate_account({}) == true",
            status
        );
    }
}

#[test]
fn test_rotate_account_false_cases() {
    for status in [400, 503, 529, 200, 502] {
        assert!(
            !should_rotate_account(status, None),
            "Expected should_rotate_account({}) == false",
            status
        );
    }
}

// ===== Balance mode & Grace Retry tests =====

#[test]
fn test_balance_mode_disallows_grace_retry_on_429() {
    let mut retry_state = RequestRetryState::default();
    let body_with_short_delay = r#"{"error":{"message":"Resource exhausted","details":[{"@type":"type.googleapis.com/google.rpc.RetryInfo","retryDelay":"2s"}]}}"#;

    // When allow_grace is true (e.g. CacheFirst mode or single account):
    let cache_first_strategy = retry_state.determine_strategy_with_grace(
        "acc1",
        429,
        body_with_short_delay,
        None,
        false,
        true,
    );
    assert!(!should_rotate_account(429, Some(&cache_first_strategy)));

    // When allow_grace is false (Balance mode with multiple accounts):
    let mut balance_state = RequestRetryState::default();
    let balance_strategy = balance_state.determine_strategy_with_grace(
        "acc2",
        429,
        body_with_short_delay,
        None,
        false,
        false, // allow_grace = false in Balance mode
    );
    // In Balance mode, it must rotate immediately to alternate accounts!
    assert!(should_rotate_account(429, Some(&balance_strategy)));
    assert!(!matches!(balance_strategy, RetryStrategy::GraceRetry(_)));

    // Standalone determine_retry_strategy_with_grace check
    let s1 = determine_retry_strategy_with_grace(429, body_with_short_delay, false, true);
    assert!(matches!(s1, RetryStrategy::GraceRetry(_)));

    let s2 = determine_retry_strategy_with_grace(429, body_with_short_delay, false, false);
    assert!(!matches!(s2, RetryStrategy::GraceRetry(_)));
    assert!(should_rotate_account(429, Some(&s2)));
    // In Balance mode with multiple accounts, delay should be minimal (50ms) to allow instant rotation
    assert_eq!(s2, RetryStrategy::FixedDelay(Duration::from_millis(50)));
}

#[test]
fn test_balance_mode_immediate_rotation_on_all_429() {
    let mut retry_state = RequestRetryState::default();
    let bodies = [
        r#"{"error":{"message":"Resource has been exhausted (e.g. check quota).","status":"RESOURCE_EXHAUSTED"}}"#,
        r#"{"error":{"code":429,"message":"Rate limit exceeded","status":"RESOURCE_EXHAUSTED"}}"#,
        r#"{"error":{"code":429,"message":"Too Many Requests"}}"#,
    ];

    for body in bodies {
        let strategy = retry_state.determine_strategy_with_grace(
            "acc-balance",
            429,
            body,
            None,
            false,
            false, // Balance mode with multiple accounts
        );
        assert!(should_rotate_account(429, Some(&strategy)));
        assert_eq!(
            strategy,
            RetryStrategy::FixedDelay(Duration::from_millis(50))
        );
    }
}

#[test]
fn test_truncate_body_for_storage() {
    use crate::modules::proxy_db::{truncate_body_for_storage, MAX_STORED_BODY_BYTES};

    // Small body is untouched
    let small = "hello world";
    assert_eq!(
        truncate_body_for_storage(Some(small)),
        Some(small.to_string())
    );

    // Large body exceeds MAX_STORED_BODY_BYTES
    let large = "a".repeat(MAX_STORED_BODY_BYTES + 1000);
    let truncated = truncate_body_for_storage(Some(&large)).unwrap();
    assert!(truncated.contains("... [truncated: showing first"));
    assert!(truncated.len() < large.len());

    // Inline media data is sanitized
    let with_base64 = format!(r#"{{"data":"data:image/png;base64,{}"}}"#, "A".repeat(500));
    let sanitized = truncate_body_for_storage(Some(&with_base64)).unwrap();
    assert!(!sanitized.contains(&"A".repeat(500)));
    assert!(sanitized.contains("omitted"));
}

#[test]
fn test_g1_credits_classified_as_quota_exhausted() {
    let error_body = r#"{
        "error": {
            "code": 429,
            "message": "Resource has been exhausted (e.g. check quota).",
            "status": "RESOURCE_EXHAUSTED",
            "details": [
                {
                    "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                    "reason": "INSUFFICIENT_G1_CREDITS_BALANCE"
                }
            ]
        }
    }"#;

    let tracker = crate::proxy::rate_limit::RateLimitTracker::new();
    let info = tracker.parse_from_error("test_acc", 429, None, error_body, None, &[60, 300]);
    assert!(info.is_some());
    let info = info.unwrap();
    assert_eq!(
        info.reason,
        crate::proxy::rate_limit::RateLimitReason::QuotaExhausted
    );
}
