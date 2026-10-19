// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:AI
// SPDX-License-Identifier: Apache-2.0

//! Service self-registration data for Sentin8:AI.
//!
//! Output via `--print-registration` flag. The CLI runs the binary with this
//! flag and consumes the JSON to register the service in the platform DB.
//! See.

use sentin8::registration::{
    AdminScope, AdminUi, AdminUiPage, PgRole, PolicySetDecl, Registration, RelationDecl,
    ScheduleDecl, SqlMigration,
};
use utoipa::OpenApi;

const PG_ROLES: &[PgRole] = &[PgRole {
    scope: "sentin8:ai:completion:write,sentin8:ai:chat:write,sentin8:ai:embedding:write,sentin8:ai:retrieval:read",
    role: "sentin8_ai_service",
    bypass_rls: false,
    database: "sentin8",
    cross_schema_grants: &[],
}];

const ADMIN_UI_PAGES: &[AdminUiPage] = &[
    AdminUiPage {
        route: "prompts",
        label: "Prompts",
        ui_endpoint: "/v1/admin/ui/prompts",
        data_endpoint: "/v1/admin/prompts",
        icon: "0xe146",
    },
    AdminUiPage {
        route: "providers",
        label: "Providers",
        ui_endpoint: "/v1/admin/ui/providers",
        data_endpoint: "/v1/admin/providers",
        icon: "0xe8b8",
    },
    AdminUiPage {
        route: "traces",
        label: "Traces",
        ui_endpoint: "/v1/admin/ui/traces",
        data_endpoint: "/v1/admin/traces",
        icon: "0xe9d5",
    },
    AdminUiPage {
        route: "budgets",
        label: "Budgets",
        ui_endpoint: "/v1/admin/ui/budgets",
        data_endpoint: "/v1/admin/budgets",
        icon: "0xe8a3",
    },
    AdminUiPage {
        route: "dlq",
        label: "AI DLQ",
        ui_endpoint: "/v1/admin/ui/dlq",
        data_endpoint: "/v1/admin/dlq",
        icon: "0xe8b2",
    },
    AdminUiPage {
        route: "evaluations",
        label: "Evaluations",
        ui_endpoint: "/v1/admin/ui/evaluations",
        data_endpoint: "/v1/admin/evaluations",
        icon: "0xef82",
    },
    AdminUiPage {
        route: "policy-sets",
        label: "Policy Sets",
        ui_endpoint: "/v1/admin/ui/policy-sets",
        data_endpoint: "/v1/admin/policy-sets",
        icon: "0xe8b8",
    },
    AdminUiPage {
        route: "policy-decisions",
        label: "Policy Decisions",
        ui_endpoint: "/v1/admin/ui/policy-decisions",
        data_endpoint: "/v1/admin/policy-decisions",
        icon: "0xf070",
    },
];

const SQL_1_INIT: &str = include_str!("../sql/init.sql");
const SQL_2_EMBEDDING_MODEL_VERSION: &str = include_str!("../sql/v2_embedding_model_version.sql");

/// Serialize the utoipa OpenAPI spec (used for the `all` and `openapi` sections).
fn openapi_spec() -> serde_json::Value {
    serde_json::to_value(crate::openapi::AiOpenApi::openapi()).unwrap_or(serde_json::Value::Null)
}

/// Default declarative policy sets (Sentin8:Policy design /):
/// action-granular scope permits over the LIVE effective scope set. Seeded
/// `origin='platform'`, `mode='enforced'` ( - step 5 is
/// the only gate; shadow is the emergency one-UPDATE rollback lever only).
const POLICIES: &[PolicySetDecl] = &[
    PolicySetDecl {
        policy_set_name: "scope-mirror",
        description: "Action-granular scope permits for sentin8:ai over the LIVE effective scope set. Enforced - step 5 is the only gate.",
        policies: "permit(principal, action == Action::\"sentin8:ai:completion:write\", resource) when { principal.scopes.contains(\"sentin8:ai:completion:write\") };\npermit(principal, action == Action::\"sentin8:ai:chat:write\", resource) when { principal.scopes.contains(\"sentin8:ai:chat:write\") };\npermit(principal, action == Action::\"sentin8:ai:embedding:write\", resource) when { principal.scopes.contains(\"sentin8:ai:embedding:write\") };\npermit(principal, action == Action::\"sentin8:ai:retrieval:read\", resource) when { principal.scopes.contains(\"sentin8:ai:retrieval:read\") };\npermit(principal, action == Action::\"sentin8:ai:prompt:read\", resource) when { principal.scopes.contains(\"sentin8:ai:prompt:read\") || principal.scopes.contains(\"sentin8:ai:prompt:write\") };\npermit(principal, action == Action::\"sentin8:ai:prompt:write\", resource) when { principal.scopes.contains(\"sentin8:ai:prompt:write\") };",
        schema: None,
        mode: "enforced",
        default_enabled: true,
    },
];

/// Default ReBAC relation tuples (design) - none declared by this
/// service today; env admins author their own graph via the admin API.
const RELATIONS: &[RelationDecl] = &[];

/// Declarative event→work bindings (AGENTS.md "event-driven execution"):
/// the AI service consumes its own stream family directly (document
/// pipeline, embedding/summary jobs) and binds the Cron maintenance
/// schedules. Registered at enroll; the platform never hardcodes these.
///
/// `json!` is not const-callable, so the slice is leaked once per process
/// (registration runs once at boot/`--print-registration`).
fn event_triggers() -> &'static [sentin8::registration::EventTriggerDecl] {
    use std::sync::OnceLock;
    static TRIGGERS: OnceLock<&'static [sentin8::registration::EventTriggerDecl]> = OnceLock::new();
    TRIGGERS.get_or_init(|| {
        let decls = vec![
            // Document pipeline - document.uploaded events from ANY
            // vertical route to the AI direct consumer (stream family `ai`).
            sentin8::registration::EventTriggerDecl {
                event_type: "document:uploaded",
                target: serde_json::json!({ "kind": "direct", "consumer": "document-pipeline" }),
                consumer_group: crate::jobs::DOCUMENT_CONSUMER_GROUP,
                retry: serde_json::json!({ "max_retries": 3, "backoff": "exponential" }),
            },
            // Cron maintenance - trace archiving + stale re-embedding.
            sentin8::registration::EventTriggerDecl {
                event_type: "sentin8:ai:trace:archive",
                target: serde_json::json!({ "kind": "cron", "schedule_type": "ai-trace-archive" }),
                consumer_group: "sentin8-ai-maintenance",
                retry: serde_json::json!({ "max_retries": 2, "backoff": "exponential" }),
            },
            sentin8::registration::EventTriggerDecl {
                event_type: "sentin8:ai:embedding:stale",
                target: serde_json::json!({ "kind": "cron", "schedule_type": "ai-reembed-stale" }),
                consumer_group: "sentin8-ai-maintenance",
                retry: serde_json::json!({ "max_retries": 2, "backoff": "exponential" }),
            },
        ];
        Box::leak(decls.into_boxed_slice())
    })
}
/// Print the registration JSON to stdout.
///
/// With no `--section` argument, outputs the full registration object.
/// With `--section=<name>`, outputs only that section as a standalone JSON value.
/// M2M DCR workload grants (self-registration): this
/// service's own `certless:<workload>` rows, upserted by `vertical enroll`.
/// The static auth seed is retired - this declaration is the ONLY
/// provisioning path (architecture- "DCR is dynamic").
/// Cover BOTH the full-identity `-policy` spelling (policy_bus_client) and
/// the bare `{short}-policy` spelling (stat_emit); the gate's superset
/// check admits any requested subset.
const M2M_GRANTS: &[sentin8::registration::M2mGrant] = &[
    sentin8::registration::M2mGrant {
        workload: "ai-audit",
        scopes: &["sentin8:sys:audit:write"],
    },
    sentin8::registration::M2mGrant {
        workload: "sentin8:ai",
        scopes: &[
            "sentin8:bus:consume",
            "sentin8:bus:produce",
            "sentin8:stat:measure",
        ],
    },
    // `ai` registers the Bus SSE consumer too (`server.rs` builds the bus
    // client directly with the short tag) - mirror `sentin8:ai`'s scope set.
    sentin8::registration::M2mGrant {
        workload: "ai",
        scopes: &["sentin8:bus:consume", "sentin8:stat:measure"],
    },
    sentin8::registration::M2mGrant {
        workload: "ai-stat",
        scopes: &["sentin8:stat:measure"],
    },
    // The outbound proxy-back client (server.rs `outbound_m2m_source`):
    // proxy-back calls to Flow/Cron/Storage on the AI pipeline.
    sentin8::registration::M2mGrant {
        workload: "ai-proxy",
        scopes: &[
            "sentin8:flow:write",
            "sentin8:cron:write",
            "sentin8:storage:env:read",
            "sentin8:storage:env:write",
        ],
    },
    sentin8::registration::M2mGrant {
        workload: "sentin8:ai-policy",
        scopes: &["sentin8:bus:consume", "sentin8:stat:measure"],
    },
    sentin8::registration::M2mGrant {
        workload: "ai-policy",
        scopes: &["sentin8:bus:consume", "sentin8:stat:measure"],
    },
    // TLS-RLS-4 (design/sentin8-vertical-data-plane-contract.md §VDC.7): the database-free HostContextResolver’s resolve workload - cache miss calls Sys `GET /v1/resolve/hostname`.
    sentin8::registration::M2mGrant {
        workload: "sentin8-ai-tls",
        scopes: &["sentin8:sys:instances:read"],
    },
];

pub fn print(section: Option<String>) -> anyhow::Result<()> {
    let reg = Registration {
        service_type: "sentin8:ai",
        subdomain: "ai",
        health_path: "/v1/health",
        admin_scopes: &[
            // Granular vocabulary : handlers gate each
            // primitive on its `sentin8:ai:{resource}:{action}` scope.
            AdminScope::Tuple("sentin8:ai:admin", "sentin8:ai:completion:write"),
            AdminScope::Tuple("sentin8:ai:admin", "sentin8:ai:chat:write"),
            AdminScope::Tuple("sentin8:ai:admin", "sentin8:ai:embedding:write"),
            AdminScope::Tuple("sentin8:ai:admin", "sentin8:ai:retrieval:read"),
            AdminScope::Tuple("sentin8:ai:admin", "sentin8:ai:prompt:read"),
            AdminScope::Tuple("sentin8:ai:admin", "sentin8:ai:prompt:write"),
            // Policy-admin surface (policy design; per-service scope).
            AdminScope::Tuple("sentin8:ai:admin", "sentin8:ai:policy:read"),
            AdminScope::Tuple("sentin8:ai:admin", "sentin8:ai:policy:write"),
        ],
        error_codes: &[],
        consent_providers: &[],
        consent_flows: &[],
        admin_ui: Some(AdminUi {
            label: "AI",
            icon: "0xe146",
            service_flag: "ai",
            pages: ADMIN_UI_PAGES,
        }),
        sql_migrations: vec![
            SqlMigration {
                version: 1,
                name: "init",
                sql: SQL_1_INIT,
            },
            SqlMigration {
                version: 2,
                name: "embedding_model_version",
                sql: SQL_2_EMBEDDING_MODEL_VERSION,
            },
        ],
        pg_roles: PG_ROLES,
        policies: POLICIES,
        relations: RELATIONS,
        event_triggers: event_triggers(),
        // Declarative maintenance schedules (SDD §2.4) - provisioned by
        // `vertical enroll`, fired by cron against the internal proxy-back
        // endpoint (no boot-time cron calls). Weekly trace archive
        // (Sundays 03:00) + nightly stale re-embedding (daily 04:00).
        schedules: &[
            ScheduleDecl {
                schedule_type: "ai-trace-archive",
                cron_expression: "0 3 * * 0",
                timezone: "UTC",
                target_config: r#"{"internalPath": "/v1/internal", "scheduleType": "ai-trace-archive"}"#,
                max_retries: 3,
            },
            ScheduleDecl {
                schedule_type: "ai-reembed-stale",
                cron_expression: "0 4 * * *",
                timezone: "UTC",
                target_config: r#"{"internalPath": "/v1/internal", "scheduleType": "ai-reembed-stale"}"#,
                max_retries: 3,
            },
        ],
        audit_findings: None,
        service_actions: None,
        m2m_grants: Some(M2M_GRANTS),
        openapi_url: "/openapi.json",
        openapi: openapi_spec,
    };
    sentin8::registration::print_registration(section, &reg, openapi_spec)
}
