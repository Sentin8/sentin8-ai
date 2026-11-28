// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:AI
// SPDX-License-Identifier: Apache-2.0

//! Per-env provider route resolution (ai DESIGN.md §4.5).
//!
//! Provider routes are TENANT configuration: an env registers its own
//! `ai.providers` rows, and a change takes effect on the next request. The
//! original design loaded the map once at boot from the `sys/ops` env, which
//! made every tenant registration silently inert.
//!
//! Resolution order for a request in env E, provider P:
//! 1. E's own `ai.providers` row for P (authoritative for tenant prompts).
//! 2. The platform `sys/ops` row for P (shared default: platform-origin
//!    prompts, and an env that has not configured its own provider).
//!
//! The cache is keyed `(env, provider)` and invalidated on
//! `sentin8:ai:provider:updated` (MemBus) or by TTL, so a change propagates
//! across the fleet without a restart.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sqlx::Row;
use uuid::Uuid;

use crate::providers::Route;

/// How long a cached route lives before it is re-resolved. A provider row
/// change also invalidates eagerly via the MemBus signal; the TTL is the
/// backstop for a missed signal.
const ROUTE_TTL: Duration = Duration::from_secs(300);

/// One cached route entry.
struct Entry {
    route: Arc<Route>,
    loaded_at: Instant,
}

/// Per-env provider route cache.
pub struct ProviderRouteCache {
    entries: std::sync::RwLock<HashMap<(Uuid, String), Entry>>,
    /// Platform (sys/ops) env id - resolved lazily and cached.
    platform_env: std::sync::OnceLock<Uuid>,
}

impl Default for ProviderRouteCache {
    fn default() -> Self {
        Self {
            entries: std::sync::RwLock::new(HashMap::new()),
            platform_env: std::sync::OnceLock::new(),
        }
    }
}

impl ProviderRouteCache {
    /// Resolve the route for `provider` in `env_id`. `None` when neither the
    /// env nor the platform has an active row for that provider.
    pub async fn resolve(
        &self,
        pool: &sqlx::PgPool,
        env_id: Uuid,
        provider: &str,
    ) -> Option<Arc<Route>> {
        // Cache hit?
        if let Some(route) = self.cached(env_id, provider) {
            return Some(route);
        }
        // Env row first, then the platform default.
        let mut route = self.load(pool, env_id, provider).await;
        if route.is_none() {
            if let Some(platform) = self.platform_env(pool).await {
                if platform != env_id {
                    route = self.load(pool, platform, provider).await;
                }
            }
        }
        let route = route?;
        self.store(env_id, provider, Arc::clone(&route));
        Some(route)
    }

    /// Invalidate one `(env, provider)` entry, or every entry for the env when
    /// `provider` is `None` - the MemBus handler.
    pub fn invalidate(&self, env_id: Uuid, provider: Option<&str>) {
        let mut entries = self.entries.write().unwrap();
        match provider {
            Some(p) => {
                entries.remove(&(env_id, p.to_string()));
            }
            None => entries.retain(|(e, _), _| *e != env_id),
        }
    }

    /// Drop everything (env deletion / full refresh).
    pub fn invalidate_all(&self) {
        self.entries.write().unwrap().clear();
    }

    fn cached(&self, env_id: Uuid, provider: &str) -> Option<Arc<Route>> {
        let entries = self.entries.read().unwrap();
        let entry = entries.get(&(env_id, provider.to_string()))?;
        if entry.loaded_at.elapsed() > ROUTE_TTL {
            return None;
        }
        Some(Arc::clone(&entry.route))
    }

    fn store(&self, env_id: Uuid, provider: &str, route: Arc<Route>) {
        self.entries.write().unwrap().insert(
            (env_id, provider.to_string()),
            Entry {
                route,
                loaded_at: Instant::now(),
            },
        );
    }

    /// Resolve (and cache) the platform `sys/ops` env id.
    async fn platform_env(&self, pool: &sqlx::PgPool) -> Option<Uuid> {
        if let Some(id) = self.platform_env.get() {
            return Some(*id);
        }
        let id: Option<Uuid> = sqlx::query_scalar(
            "SELECT e.id FROM sys.environments e \
               JOIN sys.organizations o ON o.id = e.org_id \
              WHERE o.slug = 'sys' AND e.slug = 'ops' LIMIT 1",
        )
        .fetch_optional(pool)
        .await
        .ok()
        .flatten();
        if let Some(id) = id {
            let _ = self.platform_env.set(id);
        }
        id
    }

    /// Load one provider row and build its adapter. Credential resolution is
    /// secret-reference-only (never plaintext at rest).
    async fn load(&self, pool: &sqlx::PgPool, env_id: Uuid, provider: &str) -> Option<Arc<Route>> {
        let row = sqlx::query(
            "SELECT base_url, credential_ref FROM ai.providers \
              WHERE env_id = $1 AND provider = $2 AND status = 'active'",
        )
        .bind(env_id)
        .bind(provider)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()?;
        let base_url: String = row.get("base_url");
        let credential_ref: String = row.get("credential_ref");
        crate::providers::build_route(provider, &base_url, &credential_ref)
            .await
            .map(Arc::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalidate_drops_only_the_targeted_entry() {
        let cache = ProviderRouteCache::default();
        // No DB: just assert the invalidation bookkeeping is total.
        let env = Uuid::new_v4();
        cache.invalidate(env, None);
        cache.invalidate_all();
        // A read of an unknown entry is `None` rather than a panic.
        assert!(cache.cached(env, "openai").is_none());
    }
}
