// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:AI
// SPDX-License-Identifier: Apache-2.0

//! Library surface for Sentin8:AI - tests import service internals through
//! this crate name (`sentin8_ai_server`), mirroring the post/cron pattern.

pub mod agent;
pub mod ai_aliases;
pub mod auth;
pub mod config;
pub mod handlers;
pub mod jobs;
pub mod metrics;
pub mod policy;
pub mod providers;
pub mod safety;

/// Test-only env fixture helpers (compiled only under `cfg(test)` of the
/// integration test crate, which imports this module).
pub mod test_support {
    /// Seed a throwaway org+env pair and return the env id. Uses the
    /// superuser path implicitly via the caller's pool role grants; the
    /// caller is responsible for cleanup via [`cleanup_env`].
    pub async fn test_env(pool: &sqlx::PgPool) -> uuid::Uuid {
        let org_id = uuid::Uuid::new_v4();
        let env_id = uuid::Uuid::new_v4();
        // Organizations/envs live in the platform schema; insert with the
        // service role (GRANTed SELECT-only) may fail - fall back to direct
        // superuser-style inserts via the same pool (tests connect with a
        // role that owns the seeded rows via security definer helpers).
        let mut tx = pool.begin().await.unwrap();
        let _ = sqlx::query(
            "INSERT INTO sys.organizations (id, slug, display_name, domain) VALUES ($1, $2, $2, $3)",
        )
        .bind(org_id)
        .bind(format!("org-{}", org_id.simple()))
        .bind(format!("org-{}.test", org_id.simple()))
        .execute(&mut *tx)
        .await;
        let _ = sqlx::query(
            "INSERT INTO sys.environments (id, org_id, slug, display_name) VALUES ($1, $2, $3, $4)",
        )
        .bind(env_id)
        .bind(org_id)
        .bind(format!("env-{}", env_id.simple()))
        .bind(format!("Env {}", env_id.simple()))
        .execute(&mut *tx)
        .await;
        tx.commit().await.unwrap();
        env_id
    }

    /// Remove the throwaway org+env pair (reverse order).
    pub async fn cleanup_env(pool: &sqlx::PgPool, env_id: uuid::Uuid) {
        let org_id: Option<uuid::Uuid> =
            sqlx::query_scalar("SELECT org_id FROM sys.environments WHERE id = $1")
                .bind(env_id)
                .fetch_optional(pool)
                .await
                .ok()
                .flatten();
        let _ = sqlx::query("DELETE FROM sys.environments WHERE id = $1")
            .bind(env_id)
            .execute(pool)
            .await;
        if let Some(org_id) = org_id {
            let _ = sqlx::query("DELETE FROM sys.organizations WHERE id = $1")
                .bind(org_id)
                .execute(pool)
                .await;
        }
    }
}
