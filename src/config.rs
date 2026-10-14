// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:AI
// SPDX-License-Identifier: Apache-2.0

//! AI configuration loaded from environment variables.
//!
//! Provider credentials are NEVER carried here — the provider registry rows
//! hold secret *references* resolved via Sentin8:Secrets at call time
//! (architecture-).

use std::env;

use sentin8::auth::client::{Client as AuthClient, ClientOptions};

#[derive(Clone)]
pub struct AiConfig {
    pub port: u16,
    pub database_url: String,
    pub sentin8_auth_issuer: String,
    pub sentin8_auth_jwks_url: String,
    /// Valkey URL for the exact-match response cache.
    pub valkey_url: String,
    /// Sentin8:Bus URL (D5, RS §3): the embedding consumer connects to
    /// BUS, never to Valkey. The old code passed `valkey_url` into
    /// `build_with_dcr` — a copy-paste defect that left the consumer
    /// silently offline (it connected to the Valkey port and never
    /// consumed a stream).
    pub bus_url: String,
    /// Shared Auth client — constructed once so the discovery and JWKS
    /// caches are reused across every request (5-minute TTL each).
    /// Cloning is cheap (the caches live behind an `Arc`).
    pub auth_client: AuthClient,
}

impl std::fmt::Debug for AiConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Client internals are opaque (reqwest clients) — the config debug
        // shape only ever reports URLs and flags, never credentials.
        f.debug_struct("AiConfig")
            .field("port", &self.port)
            .finish()
    }
}

/// Resolve a provider credential secret reference (
/// migration). References use the `backend://path` URI form of
/// `sentin8-secrets::SecretRef`; resolution goes through the shared
/// `sentin8-secrets` backend chain (`resolve_credential`):
///
/// 1. `secrets://` — the Sentin8:Secrets service (production path).
/// 2. `env://` — env mapping. Bare references (the v1 registry format) are
///
///   treated as AI env keys: `SENTIN8_AI_PROVIDER_KEY_<SCREAMING_PATH>`
///
///   (dev bootstrap; the path is upper-cased with separators → `_`).
/// 3. `file://` — the local file backend for development.
///
/// A `SecretValue` never leaves this function — it is converted to the
/// credential immediately and zeroized on drop.
async fn credential_from_ref(
    credential_ref: &str,
) -> Option<sentin8_secrets_sdk::secrets::SecretValue> {
    // Bare reference (no `://`) — v1 registry format → AI env key.
    if !credential_ref.contains("://") {
        let env_key = format!(
            "SENTIN8_AI_PROVIDER_KEY_{}",
            credential_ref.to_uppercase().replace(['-', '.', '/'], "_")
        );
        return env::var(&env_key)
            .ok()
            .map(|k| sentin8_secrets_sdk::secrets::SecretValue::new(k.into_bytes()));
    }

    let reference = sentin8_secrets_sdk::secrets::SecretRef::parse(credential_ref).ok()?;
    match reference.backend.as_str() {
        // AI-local env mapping (existing dev contract — `env://` in the AI
        // registry maps to `SENTIN8_AI_PROVIDER_KEY_*`, NOT the platform
        // `SENTIN8_SECRETS_*` namespace the shared EnvResolver uses).
        "env" => {
            let env_key = format!(
                "SENTIN8_AI_PROVIDER_KEY_{}",
                reference.path.to_uppercase().replace(['-', '.', '/'], "_")
            );
            env::var(&env_key)
                .ok()
                .map(|k| sentin8_secrets_sdk::secrets::SecretValue::new(k.into_bytes()))
        }
        // AI-local file backend (dev): raw file read, as before.
        "file" => {
            let path = std::path::PathBuf::from(&reference.path);
            std::fs::read(&path)
                .ok()
                .map(sentin8_secrets_sdk::secrets::SecretValue::new)
        }
        // Standard chain — Sentin8:Secrets service backend (production path).
        "secrets" | "service" | "sentin8-secrets" => {
            sentin8_secrets_sdk::secrets::resolve_credential(credential_ref)
                .await
                .ok()
        }
        other => {
            tracing::warn!(
                backend = other,
                "unsupported secret backend for provider credential"
            );
            None
        }
    }
}

/// Build the resolved [`crate::providers::ProviderCredential`] for a
/// registry row's secret reference. Empty credential on failure (the call
/// will 401 at the provider — logged at resolution time; the secret itself
/// is never logged).
pub async fn credential_for(credential_ref: &str) -> crate::providers::ProviderCredential {
    match credential_from_ref(credential_ref).await {
        Some(secret) => match secret.into_string() {
            Ok(key) => crate::providers::ProviderCredential::Bearer(key),
            Err(e) => {
                tracing::warn!(error = %e, "provider credential is not valid UTF-8");
                crate::providers::ProviderCredential::Bearer(String::new())
            }
        },
        None => {
            tracing::warn!(
                credential_ref,
                "credential secret not resolved — provider calls will fail with 401"
            );
            crate::providers::ProviderCredential::Bearer(String::new())
        }
    }
}

impl AiConfig {
    pub fn from_env() -> Self {
        let cfg = sentin8::config::Sentin8Config::from_env();
        let sentin8_auth_issuer =
            env::var("SENTIN8_AUTH_ISSUER").unwrap_or_else(|_| cfg.sentin8_auth_issuer());
        Self {
            port: env::var("SENTIN8_AI_PORT")
                .expect("SENTIN8_AI_PORT must be set by captain")
                .parse()
                .expect("SENTIN8_AI_PORT must be a valid u16"),
            database_url: env::var("SENTIN8_AI_DB_DSN").unwrap_or_else(|_| {
                env::var("DATABASE_URL").unwrap_or_else(|_| {
                    sentin8::config::Sentin8Config::default_database_url().to_string()
                })
            }),
            sentin8_auth_jwks_url: env::var("SENTIN8_AUTH_JWKS_URL")
                .unwrap_or_else(|_| cfg.sentin8_auth_jwks_url()),
            valkey_url: env::var("SENTIN8_AI_VALKEY_URL")
                .unwrap_or_else(|_| sentin8::config::Sentin8Config::valkey_url_from_env()),
            bus_url: env::var("SENTIN8_AI_BUS_URL").unwrap_or_else(|_| cfg.sentin8_bus_url()),
            auth_client: AuthClient::new(ClientOptions {
                base_url: sentin8_auth_issuer.clone(),
                ..Default::default()
            }),
            sentin8_auth_issuer,
        }
    }
}
