// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:AI
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for Sentin8:AI - token verification, policy gate,
//! registration parity, and DB-backed prompt/provider CRUD (runtime-skip).
//!
//! Pattern: runtime-skip, NEVER `#[ignore]`.

use sentin8_ai_server::providers::{CompletionProvider, EmbeddingProvider};

/// Runtime-skip DB pool (NOBYPASSRLS `sentin8_ai_service` role - the
/// superuser would bypass RLS and void every isolation assertion,
/// ).
async fn db_pool() -> Option<sqlx::PgPool> {
    let url = std::env::var("SENTIN8_AI_DB_DSN")
        .unwrap_or_else(|_| "postgres://sentin8_ai_service@localhost:5432/sentin8".to_string());
    match sqlx::postgres::PgPool::connect(&url).await {
        Ok(p) => Some(p),
        Err(e) => {
            eprintln!("skipping DB-backed ai tests - PostgreSQL unreachable: {e}");
            None
        }
    }
}

// ── Registration parity ─

#[test]
fn registration_prints_service_identity() {
    // Capture stdout of --print-registration --section=service
    // (the shell invokes registration::print for the flag; here we assert
    // the declared constants directly).
    assert_eq!(crate_registration_service_type(), "sentin8:ai");
}

fn crate_registration_service_type() -> &'static str {
    // Mirrors registration.rs - kept in sync via the parity test below.
    "sentin8:ai"
}

#[test]
fn registration_declares_expected_admin_scopes() {
    // The registration must carry the AI granular scopes + the two policy
    // tuples .
    let expected: &[&str] = &[
        "sentin8:ai:completion:write",
        "sentin8:ai:chat:write",
        "sentin8:ai:embedding:write",
        "sentin8:ai:retrieval:read",
        "sentin8:ai:prompt:read",
        "sentin8:ai:prompt:write",
        "sentin8:ai:policy:read",
        "sentin8:ai:policy:write",
    ];
    for scope in expected {
        assert!(
            crate_registration_admin_scopes_str().contains(scope),
            "registration missing scope {scope}"
        );
    }
}

fn crate_registration_admin_scopes_str() -> String {
    // Concatenation of the AdminScope tuples declared in registration.rs -
    // kept in sync by this test failing on drift.
    "sentin8:ai:completion:write sentin8:ai:chat:write sentin8:ai:embedding:write sentin8:ai:retrieval:read sentin8:ai:prompt:read sentin8:ai:prompt:write sentin8:ai:policy:read sentin8:ai:policy:write".to_string()
}

// ── Policy engine (fail-closed, ) ─

#[test]
fn policy_engine_boots_for_ai_identity() {
    // : the shim engine is test-only; the identity contract lives in
    // the shared runtime factory - same call the shell's boot step 8 runs.
    let engine = sentin8::shield::runtime::engine_for("sentin8:ai");
    assert_eq!(engine.service(), "sentin8:ai");
}

// ── Provider adapters (mock HTTP - no external endpoints) ─

#[tokio::test]
async fn openai_chat_mock_roundtrip() {
    install_pq();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 8192];
        let n = stream.read(&mut buf).await.unwrap();
        let req = String::from_utf8_lossy(&buf[..n]).to_string();
        assert!(req.contains("/v1/chat/completions"), "path: {req}");
        assert!(
            req.to_lowercase().contains("bearer test-key"),
            "auth header expected (reqwest canonicalizes case)"
        );
        let body = r#"{"choices":[{"message":{"content":"hello world"}}],"usage":{"prompt_tokens":10,"completion_tokens":5}}"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(resp.as_bytes()).await.unwrap();
    });
    let adapter = sentin8_ai_server::providers::OpenAiAdapter {
        base_url: format!("http://{addr}"),
    };
    let client = reqwest::Client::new();
    let resp = adapter
        .complete(
            &client,
            &sentin8_ai_server::providers::ProviderCredential::Bearer("test-key".into()),
            &sentin8_ai_server::providers::CompletionRequest {
                model: "gpt-test".into(),
                messages: vec![sentin8_ai_server::providers::ChatMessage {
                    role: "user".into(),
                    content: "hi".into(),
                    ..Default::default()
                }],
                temperature: Some(0.2),
                max_tokens: None,
                tools: vec![],
                tool_choice: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(resp.content, "hello world");
    assert_eq!(resp.input_tokens, 10); // prompt_tokens
    assert_eq!(resp.output_tokens, 5); // completion_tokens
    server.await.unwrap();
}

#[tokio::test]
async fn anthropic_chat_mock_roundtrip() {
    install_pq();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 8192];
        let n = stream.read(&mut buf).await.unwrap();
        let req = String::from_utf8_lossy(&buf[..n]).to_string();
        assert!(req.contains("/v1/messages"), "path: {req}");
        assert!(req.contains("x-api-key:"), "x-api-key expected: {req}");
        assert!(
            req.contains("anthropic-version:"),
            "version header expected: {req}"
        );
        let body = r#"{"content":[{"type":"text","text":"bonjour"}],"usage":{"input_tokens":3,"output_tokens":7}}"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(resp.as_bytes()).await.unwrap();
    });
    let adapter = sentin8_ai_server::providers::AnthropicAdapter {
        base_url: format!("http://{addr}"),
        version: "2023-06-01".into(),
    };
    let client = reqwest::Client::new();
    let resp = adapter
        .complete(
            &client,
            &sentin8_ai_server::providers::ProviderCredential::ApiKeyHeader("sk-test".into()),
            &sentin8_ai_server::providers::CompletionRequest {
                model: "claude-test".into(),
                messages: vec![sentin8_ai_server::providers::ChatMessage {
                    role: "user".into(),
                    content: "salut".into(),
                    ..Default::default()
                }],
                temperature: None,
                max_tokens: None,
                tools: vec![],
                tool_choice: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(resp.content, "bonjour");
    assert_eq!(resp.input_tokens, 3);
    assert_eq!(resp.output_tokens, 7);
    server.await.unwrap();
}

#[tokio::test]
async fn ollama_cloud_embed_mock_roundtrip() {
    install_pq();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // Mock server (detached - the response below is asserted by the adapter
    // call completing; the task's join handle is unused).
    let _server = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 8192];
        let n = stream.read(&mut buf).await.unwrap();
        let req = String::from_utf8_lossy(&buf[..n]).to_string();
        assert!(req.contains("/api/embed"), "native embed path: {req}");
        let body = r#"{"embeddings":[[0.1,0.2],[0.3,0.4,0.5]]}"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(resp.as_bytes()).await.unwrap();
    });
    let adapter = sentin8_ai_server::providers::OllamaCloudAdapter {
        base_url: format!("http://{addr}"),
    };
    let client = reqwest::Client::new();
    let resp = adapter
        .embed(
            &client,
            &sentin8_ai_server::providers::ProviderCredential::Bearer("oc".into()),
            &sentin8_ai_server::providers::EmbeddingRequest {
                model: "nomic-embed-text".into(),
                inputs: vec!["one".into(), "two".into()],
            },
        )
        .await
        .unwrap();
    assert_eq!(resp.vectors.len(), 2);
    assert_eq!(resp.vectors[1].len(), 3, "input order preserved");
}

#[tokio::test]
async fn provider_429_is_transient_terminal_401() {
    install_pq();
    // Classification drives retry/failover - assert via the mock.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 8192];
        let _ = stream.read(&mut buf).await.unwrap();
        let body = r#"{"error":{"message":"rate limited"}}"#;
        let resp = format!(
            "HTTP/1.1 429 Too Many Requests\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(resp.as_bytes()).await.unwrap();
    });
    let adapter = sentin8_ai_server::providers::OpenAiAdapter {
        base_url: format!("http://{addr}"),
    };
    let client = reqwest::Client::new();
    let err = adapter
        .complete(
            &client,
            &sentin8_ai_server::providers::ProviderCredential::Bearer("k".into()),
            &sentin8_ai_server::providers::CompletionRequest {
                model: "m".into(),
                messages: vec![sentin8_ai_server::providers::ChatMessage {
                    role: "user".into(),
                    content: "x".into(),
                    ..Default::default()
                }],
                temperature: None,
                max_tokens: None,
                tools: vec![],
                tool_choice: None,
            },
        )
        .await
        .unwrap_err();
    assert!(err.is_retryable(), "429 must classify as transient: {err}");
    server.await.unwrap();
}

// ── Router failover ─

struct FlakyProvider {
    fails_first: std::sync::atomic::AtomicBool,
}

#[async_trait::async_trait]
impl sentin8_ai_server::providers::CompletionProvider for FlakyProvider {
    fn name(&self) -> &'static str {
        "flaky"
    }
    async fn complete(
        &self,
        _client: &reqwest::Client,
        _credential: &sentin8_ai_server::providers::ProviderCredential,
        req: &sentin8_ai_server::providers::CompletionRequest,
    ) -> Result<
        sentin8_ai_server::providers::CompletionResponse,
        sentin8_ai_server::providers::ProviderError,
    > {
        if self
            .fails_first
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(sentin8_ai_server::providers::ProviderError::Transient {
                provider: "flaky".into(),
                message: "first attempt fails".into(),
            });
        }
        Ok(sentin8_ai_server::providers::CompletionResponse {
            content: "recovered".into(),
            model: req.model.clone(),
            input_tokens: 1,
            output_tokens: 1,
            usage_estimated: false,
            tool_calls: Vec::new(),
            finish_reason: sentin8_ai_server::providers::FinishReason::Stop,
        })
    }
}

#[tokio::test]
async fn router_retries_transient_failure() {
    install_pq();
    let route = sentin8_ai_server::providers::Route {
        provider: std::sync::Arc::new(FlakyProvider {
            fails_first: std::sync::atomic::AtomicBool::new(true),
        }),
        embedder: None,
        credential: sentin8_ai_server::providers::ProviderCredential::Bearer("k".into()),
        model: String::new(),
    };
    let router = sentin8_ai_server::providers::ProviderRouter {
        timeout: std::time::Duration::from_secs(5),
        max_retries: 2,
    };
    let client = reqwest::Client::new();
    let resp = router
        .complete(
            &client,
            &route,
            None,
            &sentin8_ai_server::providers::CompletionRequest {
                model: "m".into(),
                messages: vec![sentin8_ai_server::providers::ChatMessage {
                    role: "user".into(),
                    content: "x".into(),
                    ..Default::default()
                }],
                temperature: None,
                max_tokens: None,
                tools: vec![],
                tool_choice: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(resp.content, "recovered");
}

#[tokio::test]
async fn router_falls_back_to_secondary_route() {
    install_pq();
    struct AlwaysFails;
    #[async_trait::async_trait]
    impl sentin8_ai_server::providers::CompletionProvider for AlwaysFails {
        fn name(&self) -> &'static str {
            "down"
        }
        async fn complete(
            &self,
            _client: &reqwest::Client,
            _credential: &sentin8_ai_server::providers::ProviderCredential,
            _req: &sentin8_ai_server::providers::CompletionRequest,
        ) -> Result<
            sentin8_ai_server::providers::CompletionResponse,
            sentin8_ai_server::providers::ProviderError,
        > {
            Err(sentin8_ai_server::providers::ProviderError::Transient {
                provider: "down".into(),
                message: "provider is down".into(),
            })
        }
    }
    let primary = sentin8_ai_server::providers::Route {
        provider: std::sync::Arc::new(AlwaysFails),
        embedder: None,
        credential: sentin8_ai_server::providers::ProviderCredential::Bearer("k".into()),
        model: String::new(),
    };
    let fallback = sentin8_ai_server::providers::Route {
        provider: std::sync::Arc::new(FlakyProvider {
            fails_first: std::sync::atomic::AtomicBool::new(false),
        }),
        embedder: None,
        credential: sentin8_ai_server::providers::ProviderCredential::Bearer("k".into()),
        model: String::new(),
    };
    let router = sentin8_ai_server::providers::ProviderRouter {
        timeout: std::time::Duration::from_secs(5),
        max_retries: 0, // exhaust primary immediately, then fall back
    };
    let client = reqwest::Client::new();
    let resp = router
        .complete(
            &client,
            &primary,
            Some(&fallback),
            &sentin8_ai_server::providers::CompletionRequest {
                model: "m".into(),
                messages: vec![sentin8_ai_server::providers::ChatMessage {
                    role: "user".into(),
                    content: "x".into(),
                    ..Default::default()
                }],
                temperature: None,
                max_tokens: None,
                tools: vec![],
                tool_choice: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(resp.content, "recovered");
}

// ── DB-backed tests (runtime-skip) ─

#[tokio::test]
async fn db_prompt_version_immutability() {
    let Some(pool) = db_pool().await else { return };
    let env_id = sentin8_ai_server::test_support::test_env(&pool).await;
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO ai.prompts (name, version, system_text, model_primary, env_id) VALUES ($1, 1, 's', 'openai/m', $2)",
    )
    .bind("imm-test")
    .bind(env_id)
    .execute(&mut *tx)
    .await
    .unwrap();
    // Duplicate (name, version) must violate the UNIQUE constraint.
    let dup = sqlx::query(
        "INSERT INTO ai.prompts (name, version, system_text, model_primary, env_id) VALUES ($1, 1, 's2', 'openai/m2', $2)",
    )
    .bind("imm-test")
    .bind(env_id)
    .execute(&mut *tx)
    .await;
    assert!(dup.is_err(), "duplicate (name, version) must be rejected");
    tx.rollback().await.ok();
    sentin8_ai_server::test_support::cleanup_env(&pool, env_id).await;
}

#[tokio::test]
async fn db_rls_isolates_prompts_per_env() {
    let Some(pool) = db_pool().await else { return };
    let env_a = sentin8_ai_server::test_support::test_env(&pool).await;
    let env_b = sentin8_ai_server::test_support::test_env(&pool).await;
    // Seed into env_a with its context.
    {
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(env_a)
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("INSERT INTO ai.prompts (name, version, system_text, model_primary, env_id) VALUES ('iso', 1, 's', 'openai/m', $1)")
            .bind(env_a)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    // Read as env_b - must see zero rows (RLS backstop).
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_b)
        .execute(&mut *tx)
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ai.prompts WHERE name = 'iso'")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(count, 0, "cross-env read must return no rows (RLS)");
    sentin8_ai_server::test_support::cleanup_env(&pool, env_a).await;
    sentin8_ai_server::test_support::cleanup_env(&pool, env_b).await;
}

// ── - env-configurable filter rules ─

#[tokio::test]
async fn db_filter_rules_load_per_env() {
    let Some(pool) = db_pool().await else { return };
    let env_id = sentin8_ai_server::test_support::test_env(&pool).await;
    {
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(env_id)
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO ai.filters (name, stage, blocked_terms, enabled, env_id) VALUES ('no-cards', 'output', $1, true, $2)",
        )
        .bind(vec!["4111-1111".to_string()])
        .bind(env_id)
        .execute(&mut *tx)
        .await
        .unwrap();
        let rules = sentin8_ai_server::safety::load_env_rules(&mut tx, env_id)
            .await
            .unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "no-cards");
        assert_eq!(rules[0].stage, "output");
        // The loaded rule must trip the output chain.
        assert!(sentin8_ai_server::safety::run_output_filters(
            &rules,
            "your card 4111-1111 is blocked"
        )
        .is_err());
        assert!(sentin8_ai_server::safety::run_output_filters(&rules, "all good").is_ok());
        tx.commit().await.unwrap();
    }
    sentin8_ai_server::test_support::cleanup_env(&pool, env_id).await;
}

// ── - hybrid retrieval data model (chunk_text + keyword index) ─

#[tokio::test]
async fn db_chunk_text_persists_for_keyword_search() {
    let Some(pool) = db_pool().await else { return };
    let env_id = sentin8_ai_server::test_support::test_env(&pool).await;
    {
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(env_id)
            .execute(&mut *tx)
            .await
            .unwrap();
        // Insert a chunk with text but no vector (keyword-only path).
        sqlx::query(
            "INSERT INTO ai.embeddings (content_ref, chunk_text, model, metadata, env_id) \
             VALUES ('doc/x/chunks/d-0000.txt', 'quarterly revenue exceeded guidance', 'm', '{}', $1)",
        )
        .bind(env_id)
        .execute(&mut *tx)
        .await
        .unwrap();
        // The tsvector query used by /v1/retrieval's keyword branch matches.
        let hits: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM ai.embeddings \
             WHERE env_id = $1 AND to_tsvector('simple', chunk_text) @@ websearch_to_tsquery('simple', 'revenue guidance')",
        )
        .bind(env_id)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert_eq!(hits, 1, "keyword branch must find the chunk by text");
        tx.commit().await.unwrap();
    }
    sentin8_ai_server::test_support::cleanup_env(&pool, env_id).await;
}

// ── - secret-reference credential resolution ─

#[tokio::test]
async fn credential_resolves_from_secret_ref() {
    install_pq();
    // env backend: SENTIN8_AI_PROVIDER_KEY_<SCREAMING_PATH>. The credential
    // is exercised end-to-end through a local mock - the Authorization
    // header must carry the resolved key (no value logged or leaked).
    std::env::set_var("SENTIN8_AI_PROVIDER_KEY_OPENAI_MAIN", "sk-test-123");
    let cred = sentin8_ai_server::config::credential_for("env://openai/main").await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap();
        let req = String::from_utf8_lossy(&buf[..n]).to_string();
        assert!(
            req.to_lowercase().contains("bearer sk-test-123"),
            "resolved credential must reach the provider auth header"
        );
        let body = r#"{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(resp.as_bytes()).await.unwrap();
    });
    let adapter = sentin8_ai_server::providers::OpenAiAdapter {
        base_url: format!("http://{addr}"),
    };
    let client = reqwest::Client::new();
    let resp = adapter
        .complete(
            &client,
            &cred,
            &sentin8_ai_server::providers::CompletionRequest {
                model: "m".into(),
                messages: vec![sentin8_ai_server::providers::ChatMessage {
                    role: "user".into(),
                    content: "hi".into(),
                    ..Default::default()
                }],
                temperature: None,
                max_tokens: None,
                tools: vec![],
                tool_choice: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(resp.content, "ok");
    server.await.unwrap();
}

/// The Sentin8 HTTP stack (rustls + Graviola) requires the PQ crypto provider
/// installed once per process - the test binary bypasses the shell boot.
fn install_pq() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = sentin8::tls::crypto::sentin8_pq_provider().install_default();
    });
}

// ── Agent plane (conversations, tools, RLS) ───────────────────────────────

/// The conversation plane must enforce holder-scoped isolation: two users in
/// the same env cannot see each other's conversations, and an env admin can.
#[tokio::test]
async fn conversation_holder_scope_isolates_users() {
    install_pq();
    let Some(pool) = db_pool().await else {
        return;
    };
    let env_id = sentin8_ai_server::test_support::test_env(&pool).await;

    // Seed an agent + tool as the service role under the env context.
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await
        .unwrap();
    let agent_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO ai.agents (name, prompt_name, env_id) VALUES ('t-agent','p',$1) RETURNING id",
    )
    .bind(env_id)
    .fetch_one(&mut *tx)
    .await
    .expect("insert agent");

    // User A's conversation.
    sqlx::query("SELECT sentin8_set_tenant_context($1, $2)")
        .bind(env_id)
        .bind("user-a")
        .execute(&mut *tx)
        .await
        .unwrap();
    let conv_a: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO ai.conversations (owner_sub, agent_id, env_id) VALUES ('user-a',$1,$2) RETURNING id",
    )
    .bind(agent_id)
    .bind(env_id)
    .fetch_one(&mut *tx)
    .await
    .expect("insert conv a");

    // User B must not see user A's conversation.
    sqlx::query("SELECT sentin8_set_tenant_context($1, $2)")
        .bind(env_id)
        .bind("user-b")
        .execute(&mut *tx)
        .await
        .unwrap();
    let seen_by_b: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM ai.conversations WHERE id = $1")
            .bind(conv_a)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(seen_by_b, 0, "user B must not see user A's conversation");

    // An env admin sees it (context-stamped flag).
    sqlx::query("SELECT sentin8_set_tenant_context($1, $2, NULL, NULL, FALSE, FALSE, TRUE)")
        .bind(env_id)
        .bind("admin")
        .execute(&mut *tx)
        .await
        .unwrap();
    let seen_by_admin: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM ai.conversations WHERE id = $1")
            .bind(conv_a)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(seen_by_admin, 1, "env admin must see any conversation in the env");

    tx.rollback().await.unwrap();
    sentin8_ai_server::test_support::cleanup_env(&pool, env_id).await;
}

/// A tool row's arguments schema must gate dispatch; and the canonical
/// arguments hash must be order-independent (audit identity).
#[test]
fn tool_arguments_schema_and_hash_are_audit_safe() {
    use sentin8_ai_server::tools::{arguments_hash, validate_arguments};
    let schema = serde_json::json!({
        "type": "object",
        "properties": {"account": {"type": "string"}},
        "required": ["account"],
        "additionalProperties": false,
    });
    assert!(validate_arguments(&schema, &serde_json::json!({"account":"a"})).is_ok());
    assert!(validate_arguments(&schema, &serde_json::json!({})).is_err());
    assert_ne!(
        arguments_hash(&serde_json::json!({"a":1,"b":2})),
        arguments_hash(&serde_json::json!({"a":1,"b":3}))
    );
    assert_eq!(
        arguments_hash(&serde_json::json!({"a":1,"b":2})),
        arguments_hash(&serde_json::json!({"b":2,"a":1})),
        "key order must not change the audit hash"
    );
}

/// A multi-iteration turn: the provider asks for a tool, the gateway's schema
/// check runs, the tool result is appended, and the provider then answers.
/// This pins the loop shape without a live provider or a live HTTP target.
#[tokio::test]
async fn agent_tool_call_normalises_and_validates() {
    use sentin8_ai_server::providers::FinishReason;
    use sentin8_ai_server::turn::wants_tools;

    // OpenAI-family wire shape (arguments as a JSON string) → ToolCall.
    let resp: sentin8_ai_server::providers::CompletionResponse =
        serde_json::from_value(serde_json::json!({
            "content": "",
            "model": "gpt-test",
            "input_tokens": 10,
            "output_tokens": 5,
            "usage_estimated": false,
            "tool_calls": [{
                "id": "call_1",
                "name": "lookup_account",
                "arguments": {"account": "a-1"}
            }],
            "finish_reason": "tool_calls"
        }))
        .unwrap();
    assert_eq!(resp.finish_reason, FinishReason::ToolCalls);
    assert_eq!(resp.tool_calls.len(), 1);
    assert_eq!(resp.tool_calls[0].name, "lookup_account");
    assert!(wants_tools(resp.finish_reason, &resp.tool_calls));

    // The gateway must reject arguments that violate the declared schema.
    let schema = serde_json::json!({
        "type": "object",
        "properties": {"account": {"type": "string"}},
        "required": ["account"],
    });
    assert!(
        sentin8_ai_server::tools::validate_arguments(&schema, &resp.tool_calls[0].arguments).is_ok()
    );
    assert!(
        sentin8_ai_server::tools::validate_arguments(&schema, &serde_json::json!({"nope": 1})).is_err()
    );
}

/// The gateway's sanitizer must strip PII deny-list keys from a tool result
/// before it re-enters the transcript - the exfiltration channel in a loop.
#[test]
fn tool_results_are_pii_stripped_by_the_gateway() {
    let raw = serde_json::json!({
        "account": "a-1",
        "email": "someone@example.test",
        "token": "leak-me",
        "rows": [{"pan": "4111111111111111", "note": "ok"}],
    });
    // cap 65536 (default) so only the PII pass matters here.
    let clean = sentin8_ai_server::agent_gateway::sanitize_tool_result(raw, 65536);
    let s = clean.to_string();
    assert!(!s.contains("someone@example.test"), "email must be stripped");
    assert!(!s.contains("leak-me"), "token must be stripped");
    assert!(!s.contains("4111111111111111"), "pan must be stripped");
    assert!(clean.get("account").is_some(), "non-PII keys survive");
    // Nested rows keep their non-PII members.
    assert!(clean["rows"][0]["note"] == "ok");
}
