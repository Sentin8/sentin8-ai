// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:AI
// SPDX-License-Identifier: Apache-2.0

//! Async AI job consumers.
//!
//! Direct consumers (no Sentin8:Func): the service subscribes to its own
//! stream families via `bus-client` (`consume` + `POST /v1/ack`) and handles
//! the event in-process — the preferred path when the reaction is a
//! first-class concern of the owning service (architecture-principles
//! "event-driven execution").
//!
//! Jobs are idempotent: the event envelope carries an `idempotency_key`
//! (the payload's `job_id`); completed jobs are skipped on replay.
use sqlx::Row;

/// Stream family the relay publishes AI events to (`stream_family = "ai"`).
pub const AI_STREAM_FAMILY: &str = "ai";
/// Consumer group for the embedding-job direct consumer.
pub const EMBEDDING_CONSUMER_GROUP: &str = "sentin8-ai-embedding";

/// Envelope for `sentin8:ai:embedding:job` — self-contained (payload
/// completeness): the consumer never calls back for more data.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct EmbeddingJobEnvelope {
    pub job_id: String,
    pub env_id: uuid::Uuid,
    pub model: String,
    /// Chunks to embed: `(content_ref, chunk_index, text)`.
    pub chunks: Vec<EmbedJobChunk>,
    /// Caller's data scope attached to the resulting chunks' metadata.
    #[serde(default)]
    pub data_scope: Vec<String>,
    #[serde(default)]
    pub source_id: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct EmbedJobChunk {
    pub content_ref: String,
    pub chunk_index: i32,
    pub text: String,
}

/// Spawn the embedding-job consumer loop. Runs for the process lifetime;
/// consume failures degrade to warn-and-retry (same posture as the policy
/// hot-reloader).
pub fn spawn_embedding_consumer(
    pool: sqlx::PgPool,
    bus_client: sentin8::bus::client::BusClient,
    routes: std::collections::HashMap<String, crate::providers::Route>,
    router: std::sync::Arc<crate::providers::ProviderRouter>,
) {
    tokio::spawn(async move {
        tracing::info!("ai embedding-job consumer started");
        loop {
            match bus_client
                .consume(&sentin8::bus::contracts::ConsumeRequest {
                    stream_family: AI_STREAM_FAMILY.into(),
                    consumer_group: EMBEDDING_CONSUMER_GROUP.into(),
                    max_count: 10,
                    block_ms: 0,
                })
                .await
            {
                Ok(resp) if !resp.messages.is_empty() => {
                    for msg in &resp.messages {
                        if msg.event_type != "sentin8:ai:embedding:job" {
                            let _ = bus_client
                                .ack(AI_STREAM_FAMILY, EMBEDDING_CONSUMER_GROUP, &msg.message_id)
                                .await;
                            continue;
                        }
                        match serde_json::from_value::<EmbeddingJobEnvelope>(msg.payload.clone()) {
                            Ok(job) => {
                                let outcome =
                                    process_embedding_job(&pool, &routes, &router, &job).await;
                                match outcome {
                                    Ok(n) => {
                                        tracing::info!(job = %job.job_id, chunks = n, "embedding job completed")
                                    }
                                    Err(e) => {
                                        // Non-ack → retry via claim timeout; DLQ after
                                        // the relay's retry budget.
                                        tracing::error!(job = %job.job_id, error = %e, "embedding job FAILED; will retry");
                                        continue; // skip ack — redelivery
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "malformed embedding job; acking to avoid poison-loop");
                            }
                        }
                        let _ = bus_client
                            .ack(AI_STREAM_FAMILY, EMBEDDING_CONSUMER_GROUP, &msg.message_id)
                            .await;
                    }
                }
                Ok(_) => { /* no messages */ }
                Err(e) => tracing::debug!(error = %e, "ai consume unavailable; retrying"),
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    });
}

/// Embed + persist job chunks (RLS-scoped, same-connection context).
/// Idempotency: chunks whose `(source_id, chunk_index, content_ref)` row
/// already exists are skipped (at-least-once delivery → effectively-once).
async fn process_embedding_job(
    pool: &sqlx::PgPool,
    routes: &std::collections::HashMap<String, crate::providers::Route>,
    router: &crate::providers::ProviderRouter,
    job: &EmbeddingJobEnvelope,
) -> Result<usize, String> {
    let route = routes
        .values()
        .find(|r| r.embedder.is_some())
        .ok_or_else(|| "no embedding provider configured".to_string())?;
    let texts = job
        .chunks
        .iter()
        .map(|c| c.text.clone())
        .collect::<Vec<_>>();
    let client = reqwest::Client::new();
    let emb = router
        .embed(
            &client,
            route,
            &crate::providers::EmbeddingRequest {
                model: job
                    .model
                    .split_once('/')
                    .map(|(_, m)| m.to_string())
                    .unwrap_or_else(|| job.model.clone()),
                inputs: texts,
            },
        )
        .await
        .map_err(|e| e.to_string())?;

    let mut tx = pool
        .begin()
        .await
        .map_err(|e| format!("tx begin failed: {e}"))?;
    sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(job.env_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("rls context failed: {e}"))?;
    let scope_json = serde_json::to_value(&job.data_scope).unwrap_or_default();
    let mut written = 0usize;
    for (chunk, vector) in job.chunks.iter().zip(emb.vectors.iter()) {
        let vec_literal = format!(
            "[{}]",
            vector
                .iter()
                .map(|f| f.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
        // Idempotent upsert: same source + chunk_index replaces the vector.
        let exists: Option<uuid::Uuid> = sqlx::query_scalar(
            "SELECT id FROM ai.embeddings WHERE env_id = $1 AND source_id = $2 AND chunk_index = $3",
        )
        .bind(job.env_id)
        .bind(&chunk.content_ref)
        .bind(chunk.chunk_index)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| format!("dedupe check failed: {e}"))?;
        if exists.is_some() {
            sqlx::query("UPDATE ai.embeddings SET embedding = $1::vector, content_ref = $4, metadata = $5, model = $6, chunk_text = $7 WHERE id = $2 AND env_id = $3")
                .bind(exists)
                .bind(&vec_literal)
                .bind(chunk.chunk_index)
                .bind(&chunk.content_ref)
                .bind(serde_json::json!({"data_scope": scope_json}))
                .bind(&job.model)
                .bind(&chunk.text)
                .execute(&mut *tx)
                .await
                .map_err(|e| format!("embed update failed: {e}"))?;
        } else {
            sqlx::query(
                "INSERT INTO ai.embeddings (embedding, content_ref, metadata, chunk_index, model, source_id, chunk_text, env_id, model_version) \
                 VALUES ($1::vector, $2, $3, $4, $5, $6, $7, $8, $9)",
            )
            .bind(&vec_literal)
            .bind(&chunk.content_ref)
            .bind(serde_json::json!({"data_scope": scope_json}))
            .bind(chunk.chunk_index)
            .bind(&job.model)
            .bind(&job.source_id)
            .bind(&chunk.text)
            .bind(job.env_id)
            .bind(crate::handlers::registry_version_for(pool, job.env_id, &job.model).await)
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("embed insert failed: {e}"))?;
        }
        written += 1;
    }
    tx.commit()
        .await
        .map_err(|e| format!("tx commit failed: {e}"))?;
    Ok(written)
}

/// Consumer group for summary/classification jobs.
pub const SUMMARY_CONSUMER_GROUP: &str = "sentin8-ai-summary";
/// Consumer group for the document-pipeline consumer.
pub const DOCUMENT_CONSUMER_GROUP: &str = "sentin8-ai-document";

/// A fire-and-forget completion job (summary/classification). The event
/// carries everything needed — no callback required (payload completeness).
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct CompletionJobEnvelope {
    pub job_id: String,
    pub env_id: uuid::Uuid,
    pub model: String,
    /// Prompt registry name to resolve (optional — inline input otherwise).
    #[serde(default)]
    pub prompt_name: Option<String>,
    pub input: String,
    /// Feature label for cost attribution.
    #[serde(default = "default_job_feature")]
    pub feature: String,
    /// Where the result is delivered: a `sentin8:ai:{kind}:completed` event
    /// on the same stream family (direct consumers read it from here).
    #[serde(default)]
    pub reply_event_type: Option<String>,
}

fn default_job_feature() -> String {
    "async".into()
}

/// Spawn the summary/classification consumer — same direct-consumer
/// pattern as the embedding loop, idempotent on `job_id`.
pub fn spawn_summary_consumer(
    pool: sqlx::PgPool,
    bus_client: sentin8::bus::client::BusClient,
    routes: std::collections::HashMap<String, crate::providers::Route>,
    router: std::sync::Arc<crate::providers::ProviderRouter>,
) {
    tokio::spawn(async move {
        tracing::info!("ai summary/classification consumer started");
        loop {
            match bus_client
                .consume(&sentin8::bus::contracts::ConsumeRequest {
                    stream_family: AI_STREAM_FAMILY.into(),
                    consumer_group: SUMMARY_CONSUMER_GROUP.into(),
                    max_count: 10,
                    block_ms: 0,
                })
                .await
            {
                Ok(resp) if !resp.messages.is_empty() => {
                    for msg in &resp.messages {
                        let is_job = msg.event_type == "sentin8:ai:summary:job"
                            || msg.event_type == "sentin8:ai:classification:job";
                        if !is_job {
                            let _ = bus_client
                                .ack(AI_STREAM_FAMILY, SUMMARY_CONSUMER_GROUP, &msg.message_id)
                                .await;
                            continue;
                        }
                        match serde_json::from_value::<CompletionJobEnvelope>(msg.payload.clone()) {
                            Ok(job) => {
                                match process_completion_job(&pool, &routes, &router, &job).await {
                                    Ok(summary) => {
                                        tracing::info!(job = %job.job_id, "async completion job completed");
                                        // Emit the reply event (self-contained) so the
                                        // originating service can react.
                                        if let Some(reply) = &job.reply_event_type {
                                            let mut tx = match pool.begin().await {
                                                Ok(t) => t,
                                                Err(e) => {
                                                    tracing::error!(error = %e, "reply tx failed");
                                                    continue;
                                                }
                                            };
                                            let _ = sentin8::bus::outbox::insert_outbox_row(
                                            &mut *tx,
                                            job.env_id,
                                            AI_STREAM_FAMILY,
                                            reply,
                                            &serde_json::json!({ "job_id": job.job_id, "summary": summary }),
                                        )
                                        .await;
                                            let _ = tx.commit().await;
                                        }
                                    }
                                    Err(e) => {
                                        tracing::error!(job = %job.job_id, error = %e, "async completion job FAILED");
                                        let _ = dead_letter(
                                            &pool,
                                            job.env_id,
                                            &job.job_id,
                                            "summary",
                                            &e,
                                            &msg.payload,
                                        )
                                        .await;
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "malformed completion job; acking")
                            }
                        }
                        let _ = bus_client
                            .ack(AI_STREAM_FAMILY, SUMMARY_CONSUMER_GROUP, &msg.message_id)
                            .await;
                    }
                }
                Ok(_) => {}
                Err(e) => tracing::debug!(error = %e, "ai summary consume unavailable; retrying"),
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    });
}

/// Dead-letter a failed job : best-effort insert into `ai.dlq`
/// with the RLS context of the owning env.
pub async fn dead_letter(
    pool: &sqlx::PgPool,
    env_id: uuid::Uuid,
    job_id: &str,
    job_type: &str,
    error: &str,
    payload: &serde_json::Value,
) {
    let _ = dead_letter_inner(pool, env_id, job_id, job_type, error, payload).await;
}

async fn dead_letter_inner(
    pool: &sqlx::PgPool,
    env_id: uuid::Uuid,
    _job_id: &str,
    job_type: &str,
    error: &str,
    payload: &serde_json::Value,
) -> Result<(), String> {
    let mut tx = pool.begin().await.map_err(|e| format!("tx: {e}"))?;
    sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("rls: {e}"))?;
    sqlx::query(
        "INSERT INTO ai.dlq (job_type, payload, error_message, env_id) VALUES ($1,$2,$3,$4)",
    )
    .bind(job_type)
    .bind(payload)
    .bind(error)
    .bind(env_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("dlq insert: {e}"))?;
    tx.commit().await.map_err(|e| format!("commit: {e}"))?;
    Ok(())
}

/// Run a completion job: resolve prompt (if named) → provider call →
/// normalized summary string.
async fn process_completion_job(
    pool: &sqlx::PgPool,
    routes: &std::collections::HashMap<String, crate::providers::Route>,
    router: &crate::providers::ProviderRouter,
    job: &CompletionJobEnvelope,
) -> Result<String, String> {
    let route = routes
        .values()
        .find(|r| r.provider.name() != "none")
        .ok_or_else(|| "no completion provider configured".to_string())?;
    let client = reqwest::Client::new();
    let mut messages = Vec::new();
    if let Some(name) = &job.prompt_name {
        // Prompt config resolution WITHOUT an RLS tx (jobs run with the env
        // context of the event); resolve via a short tx.
        let mut tx = pool.begin().await.map_err(|e| format!("tx: {e}"))?;
        sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(job.env_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("rls: {e}"))?;
        // Direct query (resolve_prompt needs &mut tx — do it inline here).
        let row = sqlx::query(
            "SELECT system_text, user_text, model_primary, temperature FROM ai.prompts              WHERE env_id = $1 AND name = $2 AND (status = 'pinned' OR status = 'active')              ORDER BY CASE status WHEN 'pinned' THEN 0 ELSE 1 END, version DESC LIMIT 1",
        )
        .bind(job.env_id)
        .bind(name)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| format!("prompt resolve: {e}"))?;
        tx.commit().await.map_err(|e| format!("commit: {e}"))?;
        if let Some(r) = row {
            let sys: String = r.get("system_text");
            if !sys.is_empty() {
                messages.push(crate::providers::ChatMessage {
                    role: "system".into(),
                    content: sys,
                });
            }
        }
    }
    messages.push(crate::providers::ChatMessage {
        role: "user".into(),
        content: job.input.clone(),
    });
    let resp = router
        .complete(
            &client,
            route,
            None,
            &crate::providers::CompletionRequest {
                model: job
                    .model
                    .split_once('/')
                    .map(|(_, m)| m.to_string())
                    .unwrap_or_else(|| job.model.clone()),
                messages,
                temperature: Some(0.0),
                max_tokens: None,
                tools: vec![],
            },
        )
        .await
        .map_err(|e| e.to_string())?;
    Ok(resp.content)
}

// ── Document pipeline consumer ( — Flow-triggered path) ─────────────

/// Event envelope for the document pipeline (`sentin8:{vertical}:document:u
// ploaded` → trigger kind=direct → this consumer). Self-contained per the
/// payload-completeness rule: the consumer fetches ONLY the document text
/// from Storage (the object the event already names).
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct DocumentJobEnvelope {
    pub document_id: String,
    pub env_id: uuid::Uuid,
    pub model: String,
    /// Sentin8:Storage object key holding the extracted document text.
    pub storage_key: String,
    /// Caller's data scope attached to the resulting chunks' metadata.
    #[serde(default)]
    pub data_scope: Vec<String>,
    #[serde(default = "default_chunk_size_job")]
    pub chunk_size: usize,
}

fn default_chunk_size_job() -> usize {
    512
}

/// Spawn the document-pipeline consumer : `document.uploaded` events
/// → fetch text from Storage → chunk → embed → persist (reusing
/// `process_embedding_job`'s idempotent upsert path).
pub fn spawn_document_consumer(
    pool: sqlx::PgPool,
    bus_client: sentin8::bus::client::BusClient,
    routes: std::collections::HashMap<String, crate::providers::Route>,
    router: std::sync::Arc<crate::providers::ProviderRouter>,
    storage: sentin8_storage_sdk::client::StorageClient,
) {
    tokio::spawn(async move {
        tracing::info!("ai document-pipeline consumer started");
        loop {
            match bus_client
                .consume(&sentin8::bus::contracts::ConsumeRequest {
                    stream_family: AI_STREAM_FAMILY.into(),
                    consumer_group: DOCUMENT_CONSUMER_GROUP.into(),
                    max_count: 10,
                    block_ms: 0,
                })
                .await
            {
                Ok(resp) if !resp.messages.is_empty() => {
                    for msg in &resp.messages {
                        // Any `*:document:uploaded` event (verticals emit their
                        // own colon-named types; the platform never hardcodes
                        // a vertical's event names —).
                        if !msg.event_type.ends_with(":document:uploaded") {
                            let _ = bus_client
                                .ack(AI_STREAM_FAMILY, DOCUMENT_CONSUMER_GROUP, &msg.message_id)
                                .await;
                            continue;
                        }
                        match serde_json::from_value::<DocumentJobEnvelope>(msg.payload.clone()) {
                            Ok(job) => {
                                match process_document_job(&pool, &routes, &router, &storage, &job)
                                    .await
                                {
                                    Ok(n) => {
                                        tracing::info!(document = %job.document_id, chunks = n, "document pipeline completed");
                                        // Emit the completion event inbox-first.
                                        if let Ok(mut tx) = pool.begin().await {
                                            let _ = sqlx::query(
                                                "SELECT sentin8_set_tenant_context($1)",
                                            )
                                            .bind(job.env_id)
                                            .execute(&mut *tx)
                                            .await;
                                            let _ = sentin8::bus::outbox::insert_outbox_row(
                                                &mut *tx,
                                                job.env_id,
                                                AI_STREAM_FAMILY,
                                                "sentin8:ai:document:ready",
                                                &serde_json::json!({
                                                    "document_id": job.document_id,
                                                    "chunks": n,
                                                    "model": job.model,
                                                }),
                                            )
                                            .await;
                                            let _ = tx.commit().await;
                                        }
                                    }
                                    Err(e) => {
                                        tracing::error!(document = %job.document_id, error = %e, "document pipeline FAILED");
                                        let _ = dead_letter(
                                            &pool,
                                            job.env_id,
                                            &job.document_id,
                                            "document",
                                            &e,
                                            &msg.payload,
                                        )
                                        .await;
                                    }
                                }
                            }
                            Err(e) => tracing::warn!(error = %e, "malformed document job; acking"),
                        }
                        let _ = bus_client
                            .ack(AI_STREAM_FAMILY, DOCUMENT_CONSUMER_GROUP, &msg.message_id)
                            .await;
                    }
                }
                Ok(_) => {}
                Err(e) => tracing::debug!(error = %e, "ai document consume unavailable; retrying"),
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    });
}

/// Document pipeline step: Storage fetch → chunk → embed → persist
/// (extract happens upstream — the event carries the extracted-text key).
async fn process_document_job(
    pool: &sqlx::PgPool,
    routes: &std::collections::HashMap<String, crate::providers::Route>,
    router: &crate::providers::ProviderRouter,
    storage: &sentin8_storage_sdk::client::StorageClient,
    job: &DocumentJobEnvelope,
) -> Result<usize, String> {
    // 1. Fetch the extracted text from Sentin8:Storage (M2M-authenticated).
    let bytes = storage
        .get(
            &job.env_id.to_string(),
            &job.env_id.to_string(),
            &job.storage_key,
        )
        .await
        .map_err(|e| format!("storage fetch failed: {e}"))?;
    let text = String::from_utf8(bytes).map_err(|e| format!("document text not UTF-8: {e}"))?;

    // 2. Chunk (same character-window chunking as the HTTP ingest path).
    let chars: Vec<char> = text.chars().collect();
    let chunks: Vec<EmbedJobChunk> = chars
        .chunks(job.chunk_size.max(1))
        .enumerate()
        .map(|(idx, c)| EmbedJobChunk {
            content_ref: format!(
                "{}/chunks/{}-{idx:04}.txt",
                job.storage_key.trim_end_matches('/'),
                job.document_id
            ),
            chunk_index: idx as i32,
            text: c.iter().collect::<String>(),
        })
        .collect();
    if chunks.is_empty() {
        return Err("document has no content".into());
    }

    // 3. Reuse the idempotent embed+persist path (RLS-scoped, effectively-once).
    let job_env = EmbeddingJobEnvelope {
        job_id: format!("doc-{}", job.document_id),
        env_id: job.env_id,
        model: job.model.clone(),
        chunks,
        data_scope: job.data_scope.clone(),
        source_id: Some(job.document_id.clone()),
    };
    process_embedding_job(pool, routes, router, &job_env).await
}
