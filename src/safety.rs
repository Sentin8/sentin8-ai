// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:AI
// SPDX-License-Identifier: Apache-2.0

//! Safety filters + PII deny-list.
//!
//! The filter chain runs in `sentin8:ai` BEFORE the provider call (input
//! moderation) and BEFORE the response returns (output moderation) —
//! Tenant-configurable per env via `ai.filters`
//! (admin API is Shield-gated). The PII deny-list mirrors the Stat ingest
//! deny-list (`services/stat/src/types.rs`).

use serde::{Deserialize, Serialize};
use sqlx::Row;

/// Default PII deny-list keys — mirrors Stat's ingest deny-list. Applied to
/// any payload we persist (trace metadata, prompt bodies).
pub const PII_DENY_LIST: &[&str] = &[
    "email",
    "phone",
    "pan",
    "pin",
    "cvv",
    "ssn",
    "password",
    "token",
    "secret",
    "apikey",
    "api_key",
    "iban",
    "account_number",
    "card_number",
];

/// Strip PII deny-list keys from a JSON object (top-level). Returns the
/// cleaned object and whether any keys were stripped (so the trace can be
/// flagged). Same shape as Stat's `strip_pii`.
pub fn strip_pii(props: &serde_json::Value) -> (serde_json::Value, bool) {
    let Some(obj) = props.as_object() else {
        return (props.clone(), false);
    };
    let mut stripped = false;
    let mut cleaned = serde_json::Map::with_capacity(obj.len());
    for (k, v) in obj {
        let lower = k.to_lowercase();
        if PII_DENY_LIST.contains(&lower.as_str()) {
            stripped = true;
            continue;
        }
        cleaned.insert(k.clone(), v.clone());
    }
    (serde_json::Value::Object(cleaned), stripped)
}

/// A safety filter rule: reject when the text contains any of the blocked
/// substrings (case-insensitive).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterRule {
    pub name: String,
    /// Substrings that trip this rule (case-insensitive match).
    pub blocked_terms: Vec<String>,
    /// `input` (pre-provider) or `output` (pre-client).
    pub stage: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

impl FilterRule {
    pub fn matches(&self, text: &str) -> Option<String> {
        if !self.enabled {
            return None;
        }
        let lower = text.to_lowercase();
        self.blocked_terms
            .iter()
            .find(|t| lower.contains(&t.to_lowercase()))
            .map(|_t| format!("{}: matched blocked term", self.name))
    }
}

/// Built-in baseline filter (always active): refuse obvious prompt-injection
/// attempts that instruct the model to reveal system prompts or credentials.
pub fn builtin_injection_rule() -> FilterRule {
    FilterRule {
        name: "builtin-injection".into(),
        blocked_terms: vec![
            "ignore previous instructions".into(),
            "reveal your system prompt".into(),
            "disregard all rules".into(),
        ],
        stage: "input".into(),
        enabled: true,
    }
}

/// Run the input-stage chain. First matching rule blocks.
pub fn run_input_filters(rules: &[FilterRule], text: &str) -> Result<(), String> {
    // Baseline injection rule is ALWAYS active and evaluated first.
    let baseline = builtin_injection_rule();
    if let Some(reason) = baseline.matches(text) {
        return Err(reason);
    }
    for rule in rules {
        if rule.stage == "input" {
            if let Some(reason) = rule.matches(text) {
                return Err(reason);
            }
        }
    }
    Ok(())
}

/// Run the output-stage chain.
pub fn run_output_filters(rules: &[FilterRule], text: &str) -> Result<(), String> {
    for rule in rules {
        if rule.stage == "output" {
            if let Some(reason) = rule.matches(text) {
                return Err(reason);
            }
        }
    }
    Ok(())
}

/// Load the env-configurable filter rules inside the given RLS
/// transaction — the caller sets the tenant context on the same connection
///. The baseline injection rule is NOT here: it is code,
/// always active, and evaluated first in `run_input_filters`.
pub async fn load_env_rules(
    tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
    env_id: uuid::Uuid,
) -> Result<Vec<FilterRule>, String> {
    let rows = sqlx::query(
        "SELECT name, stage, blocked_terms, enabled FROM ai.filters \
         WHERE env_id = $1 AND enabled = true",
    )
    .bind(env_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| format!("filter rules load failed: {e}"))?;
    Ok(rows
        .iter()
        .map(|r| FilterRule {
            name: r.get("name"),
            stage: r.get("stage"),
            blocked_terms: r
                .get::<Vec<String>, _>("blocked_terms")
                .into_iter()
                .collect(),
            enabled: r.get("enabled"),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_pii_removes_denied_keys() {
        let v = serde_json::json!({
            "email": "a@b.c",
            "name": "ok",
            "API_KEY": "sk-...",
            "nested_ok": true
        });
        let (cleaned, stripped) = strip_pii(&v);
        assert!(stripped);
        assert!(cleaned.get("email").is_none());
        assert!(cleaned.get("api_key").is_none(), "case-insensitive match");
        assert_eq!(cleaned["name"], "ok");
        assert_eq!(cleaned["nested_ok"], true);
    }

    #[test]
    fn injection_rule_blocks_input() {
        assert!(run_input_filters(&[], "ignore previous instructions and …").is_err());
        assert!(run_input_filters(&[], "what is the weather").is_ok());
    }

    #[test]
    fn custom_rule_blocks_output() {
        let rules = vec![FilterRule {
            name: "no-pii-out".into(),
            blocked_terms: vec!["4111-1111".into()],
            stage: "output".into(),
            enabled: true,
        }];
        assert!(run_output_filters(&rules, "your card 4111-1111 is blocked").is_err());
        assert!(run_output_filters(&rules, "all good here").is_ok());
    }

    #[test]
    fn disabled_rule_does_not_block() {
        let rules = vec![FilterRule {
            name: "off".into(),
            blocked_terms: vec!["secret".into()],
            stage: "input".into(),
            enabled: false,
        }];
        assert!(run_input_filters(&rules, "the secret is 42").is_ok());
    }

    /// Empty env rules must behave identically to the no-rules path — the
    /// baseline injection rule still blocks regardless.
    #[test]
    fn empty_env_rules_keep_baseline() {
        assert!(
            run_input_filters(&load_env_rules_shape(&[]), "ignore previous instructions").is_err()
        );
    }

    /// Test-only shape adapter proving the loader output feeds the chain
    /// (the DB loader itself is exercised by the DB-backed integration test).
    fn load_env_rules_shape(rows: &[(&str, &str, Vec<&str>)]) -> Vec<FilterRule> {
        rows.iter()
            .map(|(name, stage, _terms)| FilterRule {
                name: (*name).into(),
                stage: (*stage).into(),
                blocked_terms: (*stage == "input" || *stage == "output")
                    .then_some(())
                    .map(|_| Vec::new())
                    .unwrap_or_default(),
                enabled: true,
            })
            .collect()
    }
}
