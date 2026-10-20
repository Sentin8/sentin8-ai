// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:AI
// SPDX-License-Identifier: Apache-2.0

//! Annotated RFW alias wrappers (Dash 28.14 - the RFW renderer is
//! POST-only) for handlers bound at more than one real path. One annotated
//! handler = one path in the OpenAPI spec (utoipa resolves one
//! `__path_` struct per annotated fn), so a second BINDING needs a second
//! annotated wrapper - same handler body, alias path, same gates
//! (OAPEC design §2 rule 3).

use crate::handlers::AppState;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};

/// `POST /v1/budgets/{feature}/delete` - RFW alias of
/// `DELETE /v1/budgets/{feature}`.
#[utoipa::path(
    post,
    path = "/v1/budgets/{feature}/delete",
    params(
        ("feature" = String, Path, description = "Budget feature key"),
        ("target_env_id" = Option<String>, Query, description = "Target env (RLS context)")
    ),
    responses(
        (status = 204, description = "Budget removed (same contract as DELETE /v1/budgets/{feature})"),
    ),
    security(("sentin8:ai:prompt:write" = [])),
    tag = "ai",
)]
pub async fn budget_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<crate::handlers::TargetEnvQuery>,
    Path(feature): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    crate::handlers::delete_budget(State(state), headers, Query(q), Path(feature)).await
}

/// `POST /v1/filters/{name}/delete` - RFW alias of
/// `DELETE /v1/filters/{name}`.
#[utoipa::path(
    post,
    path = "/v1/filters/{name}/delete",
    params(
        ("name" = String, Path, description = "Filter rule name"),
        ("target_env_id" = Option<String>, Query, description = "Target env (RLS context)")
    ),
    responses(
        (status = 204, description = "Filter rule removed (same contract as DELETE /v1/filters/{name})"),
    ),
    security(("sentin8:ai:prompt:write" = [])),
    tag = "ai",
)]
pub async fn filter_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<crate::handlers::TargetEnvQuery>,
    Path(name): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    crate::handlers::delete_filter(State(state), headers, Query(q), Path(name)).await
}
