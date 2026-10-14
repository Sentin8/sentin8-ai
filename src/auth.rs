// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:AI
// SPDX-License-Identifier: Apache-2.0

//! Auth token verification for Sentin8:AI.
//!
//! Re-exports the shared types from the sentin8-auth-client SDK and provides
//! a thin wrapper matching the platform call-site convention (post/cron).

use axum::http::{HeaderMap, StatusCode};

use crate::config::AiConfig;

pub use sentin8::auth::client::AuthContext;

/// Verify the Bearer token and return the auth context.
pub async fn verify_token(
    config: &AiConfig,
    headers: &HeaderMap,
) -> Result<AuthContext, (StatusCode, String)> {
    sentin8::auth::client::verify_bearer_token(&config.auth_client, headers).await
}
