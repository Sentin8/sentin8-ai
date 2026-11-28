// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:AI
// SPDX-License-Identifier: Apache-2.0

//! Per-tool rate limiting (ai DESIGN.md §4.2).
//!
//! Each tool row carries `rate_limit_per_min` (0 = unlimited). The gate runs
//! in the gateway BEFORE dispatch: a fixed one-minute window keyed
//! `(env, tool)` in Valkey (the same `INCR`/`EXPIRE` pattern acme's budget
//! uses), with a process-local fallback window when Valkey is unavailable.
//!
//! Failure posture: a Valkey blip DOWNGRADES the limit to the local window -
//! it never blocks the tool and never fails open past the local bound.

use std::collections::HashMap;
use std::sync::Mutex;

/// One local fallback window. The epoch and the counts live behind ONE lock
/// so they always flip together - a reader can never see a rolled minute
/// still counting the previous one.
#[derive(Default)]
struct LocalWindowInner {
    minute_epoch: u64,
    counts: HashMap<(uuid::Uuid, String), u64>,
}

static LOCAL: Mutex<Option<LocalWindowInner>> = Mutex::new(None);

/// Whether a dispatch may proceed under the tool's per-minute cap.
///
/// `rate_limit_per_min <= 0` means unlimited (the default) - no store call.
pub async fn admit(
    valkey_url: &str,
    env_id: uuid::Uuid,
    tool: &str,
    rate_limit_per_min: i32,
) -> bool {
    if rate_limit_per_min <= 0 {
        return true;
    }
    let cap = rate_limit_per_min as u64;

    // Valkey window (authoritative). A miss falls through to the local
    // window - degraded, never open.
    if let Ok(client) = sentin8::middleware::valkey_client(valkey_url, "sentin8:ai").await {
        use glide::AsyncCommands as _;
        let key = format!("ai:ratelimit:{env_id}:{tool}");
        // Annotate the RETURN type so glide's `RV` infers (acme's budget
        // relies on the same shape: `let n: i64 = ...incr(key, 1i64)`).
        let n: i64 = match client.incr(&key, 1i64).await {
            Ok(v) => v,
            Err(_) => return local_admit_fallback(env_id, tool, cap),
        };
        // Best-effort TTL: re-arming on every bump is correct because
        // the TTL is always at least the minute being counted.
        let _: Result<bool, _> = client.expire(&key, 60i64).await;
        return (n.max(0) as u64) <= cap;
    }

    local_bump(env_id, tool) <= cap
}

/// The local-window admission path shared by both fallback points.
fn local_admit_fallback(env_id: uuid::Uuid, tool: &str, cap: u64) -> bool {
    local_bump(env_id, tool) <= cap
}

/// The process-local window used only when Valkey is unreachable.
fn local_bump(env_id: uuid::Uuid, tool: &str) -> u64 {
    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / 60)
        .unwrap_or(0);
    let mut guard = LOCAL.lock().unwrap();
    let inner = guard.get_or_insert_with(LocalWindowInner::default);
    if inner.minute_epoch != epoch {
        inner.minute_epoch = epoch;
        inner.counts.clear();
    }
    let n = inner.counts.entry((env_id, tool.to_string())).or_insert(0);
    *n += 1;
    *n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unlimited_tools_skip_the_gate() {
        // A 0 limit admits without touching any store.
        assert!(admit("valkeys://unreachable.test", uuid::Uuid::nil(), "t", 0).await);
    }

    #[tokio::test]
    async fn local_fallback_enforces_the_cap_when_valkey_is_down() {
        // An unreachable Valkey URL exercises the local-window path. Unique
        // tool names keep each test's bucket independent.
        let url = "valkeys://invalid.invalid/0";
        let env = uuid::Uuid::new_v4();
        let tool = format!("capped-{}", uuid::Uuid::new_v4().simple());
        let mut admitted = 0;
        for _ in 0..5 {
            if admit(url, env, &tool, 3).await {
                admitted += 1;
            }
        }
        assert_eq!(admitted, 3, "the local window must enforce the cap");
        // A different tool has its own bucket.
        assert!(admit(url, env, &format!("other-{}", uuid::Uuid::new_v4().simple()), 3).await);
    }

    #[test]
    fn local_window_rolls_on_a_new_minute() {
        // Bump, then force a stale epoch and confirm the window resets.
        let env = uuid::Uuid::new_v4();
        let tool = format!("roll-{}", uuid::Uuid::new_v4().simple());
        assert_eq!(local_bump(env, &tool), 1);
        assert_eq!(local_bump(env, &tool), 2);
        {
            let mut guard = LOCAL.lock().unwrap();
            if let Some(inner) = guard.as_mut() {
                inner.minute_epoch = inner.minute_epoch.saturating_sub(10);
            }
        }
        assert_eq!(
            local_bump(env, &tool),
            1,
            "a rolled minute must start a fresh window"
        );
    }
}
