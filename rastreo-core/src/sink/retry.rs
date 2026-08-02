use std::time::Duration;

use schemars::JsonSchema;

use crate::error::RastreoError;

/// Bounded exponential-backoff retry policy for a sink's primary delivery.
///
/// `max_attempts` counts total primary attempts: `1` disables retry and dead-letters immediately, `3` (the default) is the initial attempt plus two retries.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct SinkRetry {
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
    #[serde(default = "default_backoff_initial_ms")]
    pub backoff_initial_ms: u64,
    #[serde(default = "default_backoff_max_ms")]
    pub backoff_max_ms: u64,
}

impl Default for SinkRetry {
    fn default() -> Self {
        Self {
            max_attempts: default_max_attempts(),
            backoff_initial_ms: default_backoff_initial_ms(),
            backoff_max_ms: default_backoff_max_ms(),
        }
    }
}

fn default_max_attempts() -> u32 {
    3
}

fn default_backoff_initial_ms() -> u64 {
    100
}

fn default_backoff_max_ms() -> u64 {
    2000
}

fn next_backoff(current_ms: u64, max_ms: u64) -> u64 {
    current_ms.saturating_mul(2).min(max_ms)
}

/// Run `op` with bounded exponential backoff, returning the last error after
/// `retry.max_attempts` failures. The delay doubles each attempt, capped at
/// `backoff_max_ms`. The caller's DLQ fallback on the returned `Err` is never
/// retried here.
pub async fn retry_with_backoff<T, F, Fut>(retry: &SinkRetry, mut op: F) -> Result<T, RastreoError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, RastreoError>>,
{
    let max_attempts = retry.max_attempts.max(1);
    let mut delay_ms = retry.backoff_initial_ms.min(retry.backoff_max_ms);
    let mut attempt = 1;
    loop {
        match op().await {
            Ok(value) => return Ok(value),
            Err(err) => {
                if attempt >= max_attempts {
                    return Err(err);
                }
                if delay_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
                delay_ms = next_backoff(delay_ms, retry.backoff_max_ms);
                attempt += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sink::{SinkError, SinkErrorClass};
    use std::cell::Cell;

    fn transient_error() -> RastreoError {
        RastreoError::Sink(SinkError::new(
            SinkErrorClass::ProduceFailure,
            std::io::Error::other("transient"),
        ))
    }

    fn instant(max_attempts: u32) -> SinkRetry {
        SinkRetry {
            max_attempts,
            backoff_initial_ms: 0,
            backoff_max_ms: 0,
        }
    }

    #[tokio::test]
    async fn succeeds_after_transient_failures_within_budget() {
        let calls = Cell::new(0u32);
        let result: Result<&str, RastreoError> = retry_with_backoff(&instant(3), || {
            calls.set(calls.get() + 1);
            let n = calls.get();
            async move {
                if n < 3 {
                    Err(transient_error())
                } else {
                    Ok("delivered")
                }
            }
        })
        .await;
        assert_eq!(result.expect("delivered on the third attempt"), "delivered");
        assert_eq!(calls.get(), 3, "initial attempt plus two retries");
    }

    #[tokio::test]
    async fn returns_last_error_after_exhausting_attempts() {
        let calls = Cell::new(0u32);
        let result: Result<(), RastreoError> = retry_with_backoff(&instant(3), || {
            calls.set(calls.get() + 1);
            async move { Err(transient_error()) }
        })
        .await;
        assert!(result.is_err());
        assert_eq!(
            calls.get(),
            3,
            "exactly max_attempts primary calls, no more"
        );
    }

    #[tokio::test]
    async fn max_attempts_one_makes_exactly_one_call() {
        let calls = Cell::new(0u32);
        let result: Result<(), RastreoError> = retry_with_backoff(&instant(1), || {
            calls.set(calls.get() + 1);
            async move { Err(transient_error()) }
        })
        .await;
        assert!(result.is_err());
        assert_eq!(calls.get(), 1);
    }

    #[tokio::test]
    async fn zero_max_attempts_is_clamped_to_one_call() {
        let calls = Cell::new(0u32);
        let result: Result<(), RastreoError> = retry_with_backoff(&instant(0), || {
            calls.set(calls.get() + 1);
            async move { Err(transient_error()) }
        })
        .await;
        assert!(result.is_err());
        assert_eq!(calls.get(), 1);
    }

    #[tokio::test]
    async fn success_on_retry_never_reaches_the_dlq_fallback() {
        let primary_calls = Cell::new(0u32);
        let dlq_credits = Cell::new(0u32);
        let result: Result<(), RastreoError> = retry_with_backoff(&instant(3), || {
            primary_calls.set(primary_calls.get() + 1);
            let n = primary_calls.get();
            async move {
                if n < 2 {
                    Err(transient_error())
                } else {
                    Ok(())
                }
            }
        })
        .await;
        if result.is_err() {
            dlq_credits.set(dlq_credits.get() + 1);
        }
        assert!(result.is_ok());
        assert_eq!(primary_calls.get(), 2);
        assert_eq!(
            dlq_credits.get(),
            0,
            "a retried success must not credit the DLQ"
        );
    }

    #[tokio::test]
    async fn exhausted_retry_credits_the_dlq_exactly_once() {
        let primary_calls = Cell::new(0u32);
        let dlq_credits = Cell::new(0u32);
        let result: Result<(), RastreoError> = retry_with_backoff(&instant(3), || {
            primary_calls.set(primary_calls.get() + 1);
            async move { Err(transient_error()) }
        })
        .await;
        if result.is_err() {
            dlq_credits.set(dlq_credits.get() + 1);
        }
        assert_eq!(primary_calls.get(), 3);
        assert_eq!(
            dlq_credits.get(),
            1,
            "DLQ credited once, not per failed attempt"
        );
    }

    #[test]
    fn next_backoff_doubles_until_it_reaches_the_cap() {
        assert_eq!(next_backoff(100, 2000), 200);
        assert_eq!(next_backoff(200, 2000), 400);
        assert_eq!(next_backoff(1000, 2000), 2000);
        assert_eq!(next_backoff(1500, 2000), 2000);
        assert_eq!(next_backoff(2000, 2000), 2000);
    }

    #[test]
    fn next_backoff_saturates_instead_of_overflowing() {
        assert_eq!(next_backoff(u64::MAX, u64::MAX), u64::MAX);
    }

    #[test]
    fn default_is_three_attempts_100ms_2000ms() {
        let retry = SinkRetry::default();
        assert_eq!(retry.max_attempts, 3);
        assert_eq!(retry.backoff_initial_ms, 100);
        assert_eq!(retry.backoff_max_ms, 2000);
    }
}
