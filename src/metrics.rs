// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:AI
// SPDX-License-Identifier: Apache-2.0

//! AI inference metric emission (SDD §2.6 - MemBus transport).
//!
//! Token counts, derived cost, latency, and cache hits publish as metric
//! frames on the shared telemetry path -
//! `sentin8::shield::stat_emit::emit_metric_event` (MemBus
//! `stat:telemetry` Pub/Sub, consumed by Stat's worker;
//! fire-and-forget, log-only on failure). The shared emitter is
//! initialized by the shell boot (`boot_full` →
//! `init_stat_emitter_for_service("sentin8:ai")`, slug `ai`).

use uuid::Uuid;

/// Cost per 1M tokens (USD) - a coarse normalization used when the provider
/// does not return an explicit cost. The trace row keeps the exact token
/// counts; Stat carries this derived estimate (per-env price tables are a
/// FinOps refinement, not a gate).
const DEFAULT_INPUT_USD_PER_MTOK: f64 = 0.5;
const DEFAULT_OUTPUT_USD_PER_MTOK: f64 = 1.5;

/// Estimate the USD cost of one inference from token counts (coarse
/// normalization; exact per-provider price cards land with the FinOps
/// refinement).
pub fn estimate_cost_usd(input_tokens: u64, output_tokens: u64) -> f64 {
    (input_tokens as f64 / 1_000_000.0) * DEFAULT_INPUT_USD_PER_MTOK
        + (output_tokens as f64 / 1_000_000.0) * DEFAULT_OUTPUT_USD_PER_MTOK
}

/// Emit the inference metric set for one completed call (fire-and-forget -
/// no-op until the shell boot initialized the shared emitter; a disabled
/// emitter means the trace row still carries the spend).
pub fn emit_inference_metrics(
    env_id: Uuid,
    subject_id: &str,
    feature: &str,
    model: &str,
    input_tokens: u64,
    output_tokens: u64,
    latency_ms: i64,
    cache_hit: bool,
) {
    let cost = estimate_cost_usd(input_tokens, output_tokens);
    let base = serde_json::json!({
        "feature": feature,
        "model": model,
        "subject_id": subject_id,
    });
    let emit = |event_name: &str, metrics: serde_json::Value, props: serde_json::Value| {
        sentin8::shield::stat_emit::emit_metric_event("sentin8:ai", event_name, metrics, props);
    };
    if input_tokens > 0 {
        emit(
            "ai.token.input",
            serde_json::json!({ "tokens": input_tokens, "env_id": env_id }),
            base.clone(),
        );
    }
    if output_tokens > 0 {
        emit(
            "ai.token.output",
            serde_json::json!({ "tokens": output_tokens, "env_id": env_id }),
            base.clone(),
        );
    }
    if cost > 0.0 {
        emit(
            "ai.cost.usd",
            serde_json::json!({ "cost_usd": cost, "env_id": env_id }),
            base.clone(),
        );
    }
    emit(
        "ai.latency.ms",
        serde_json::json!({ "latency_ms": latency_ms, "env_id": env_id }),
        base.clone(),
    );
    if cache_hit {
        emit(
            "ai.cache.hit",
            serde_json::json!({ "hit": 1, "env_id": env_id }),
            base,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cost estimation is pure math - stable across restarts (dashboard
    /// rollups depend on it).
    #[test]
    fn cost_estimate_matches_per_mtok_rates() {
        // 1M input + 1M output = 0.5 + 1.5 = 2.0 USD.
        assert!((estimate_cost_usd(1_000_000, 1_000_000) - 2.0).abs() < 1e-9);
        assert_eq!(estimate_cost_usd(0, 0), 0.0);
        // 1k input + 1k output ≈ 0.002 USD.
        assert!((estimate_cost_usd(1_000, 1_000) - 0.002).abs() < 1e-9);
    }

    /// Emission before the shell boot initialized the shared emitter is a
    /// silent no-op (no panic) - every path degrades to log-only.
    #[test]
    fn emit_before_init_is_noop() {
        emit_inference_metrics(Uuid::nil(), "subj", "f", "openai/m", 10, 5, 42, false);
    }
}
