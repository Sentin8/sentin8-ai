// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:AI
// SPDX-License-Identifier: Apache-2.0

//! # ai-client
//!
//! Rust HTTP client for Sentin8:AI — the platform AI capability layer.
//!
//! Used by platform services and vertical services to consume inference
//! primitives (completion, chat, embedding), the prompt registry, and
//! retrieval. The client authenticates with a bearer token issued to the
//! calling service (granular scope `sentin8:ai:{resource}:{action}`).
//!
//! Import through the namespace facade: `use sentin8::ai::client::…`.

#![deny(missing_docs)]

use std::sync::Arc;

use sentin8_middleware::http_client::Sentin8HttpClient;
use serde::{Deserialize, Serialize};

/// Errors returned by the AI client.
#[derive(Debug, thiserror::Error)]
pub enum AiError {
    /// An HTTP request failed (transport error or non-success status; the
    /// detail includes the response body when present).
    #[error("AI HTTP error: {0}")]
    Http(String),
    /// A response body could not be decoded.
    #[error("AI response decode error: {0}")]
    Decode(String),
}

/// A chat message in the normalized envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChatMessage {
    /// Sender role (`system` | `user` | `assistant`).
    pub role: String,
    /// Message content.
    pub content: String,
}

/// Request body for `POST /v1/chat` / `POST /v1/completions`.
/// Request body for `POST /v1/chat` / `POST /v1/completions`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InferenceRequest {
    /// Prompt registry name — models/temperature/schema resolve from it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_name: Option<String>,
    /// Prompt registry version (latest when absent).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_version: Option<i32>,
    /// Chat messages (chat-style requests).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub messages: Vec<ChatMessage>,
    /// Single raw input (completion-style requests).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<String>,
    /// Feature label for cost attribution `{env_id, feature, model}`.
    #[serde(default = "default_feature")]
    pub feature: String,
    /// Model override with provider prefix: `openai/gpt-5`, `ollama/llama3`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_override: Option<String>,
    /// Completion token cap.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    /// Sampling temperature.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    /// Target environment for cross-env AI consumption.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_env_id: Option<String>,
}

fn default_feature() -> String {
    "default".into()
}

impl InferenceRequest {
    /// Completion-style shorthand: single user input, model override.
    pub fn complete(model: impl Into<String>, input: impl Into<String>) -> Self {
        Self {
            prompt_name: None,
            prompt_version: None,
            messages: Vec::new(),
            input: Some(input.into()),
            feature: default_feature(),
            model_override: Some(model.into()),
            max_tokens: None,
            temperature: None,
            target_env_id: None,
        }
    }

    /// Prompt-registry style: resolve config from the named prompt.
    pub fn from_prompt(name: impl Into<String>) -> Self {
        Self {
            prompt_name: Some(name.into()),
            prompt_version: None,
            messages: Vec::new(),
            input: None,
            feature: default_feature(),
            model_override: None,
            max_tokens: None,
            temperature: None,
            target_env_id: None,
        }
    }
}

/// Response body for inference primitives.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceResponse {
    /// The generated text.
    pub content: String,
    /// The model that served the request.
    pub model: String,
    /// The prompt used, when registry-driven.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_name: Option<String>,
    /// The prompt version used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_version: Option<i32>,
    /// Prompt token count.
    pub input_tokens: u64,
    /// Completion token count.
    pub output_tokens: u64,
    /// End-to-end latency in milliseconds.
    pub latency_ms: i64,
    /// Whether the response came from the inference cache.
    pub cache_hit: bool,
    /// Whether this is an idempotency-key replay of a prior response.
    pub idempotent_replay: bool,
}

/// Request body for `POST /v1/embeddings`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingRequest {
    /// Model with provider prefix: `openai/text-embedding-3-small`,
    /// `ollama/nomic-embed-text`.
    pub model: String,
    /// Texts to embed (response preserves order).
    pub inputs: Vec<String>,
    /// Feature label for cost attribution.
    #[serde(default = "default_feature")]
    pub feature: String,
    /// Target environment for cross-env AI consumption.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_env_id: Option<String>,
}

/// Response body for embeddings (vectors in input order).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingResponse {
    /// Vectors in input order.
    pub vectors: Vec<Vec<f32>>,
    /// The model that produced the vectors.
    pub model: String,
    /// Vector dimensionality.
    pub dims: usize,
}

/// Request body for `POST /v1/retrieval` — hybrid permission-filtered search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetrievalRequest {
    /// The natural-language query.
    pub query: String,
    /// Permission scopes constraining the searchable corpus.
    #[serde(default)]
    pub data_scope: Vec<String>,
    /// Metadata-based filters (opaque JSON).
    #[serde(default)]
    pub metadata_filters: serde_json::Value,
    /// Maximum chunks to return.
    #[serde(default = "default_top_k")]
    pub top_k: i64,
    /// Target environment for cross-env AI consumption.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_env_id: Option<String>,
}

fn default_top_k() -> i64 {
    8
}

/// A retrieved chunk with its relevance score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetrievedChunk {
    /// Chunk identity.
    pub id: uuid::Uuid,
    /// Reference to the source content.
    pub content_ref: String,
    /// Chunk metadata.
    pub metadata: serde_json::Value,
    /// Relevance score.
    pub score: f64,
}

/// Response body for `POST /v1/retrieval`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetrievalResponse {
    /// Retrieved chunks, best-first.
    pub chunks: Vec<RetrievedChunk>,
    /// Time spent embedding the query (ms).
    pub query_embedding_ms: i64,
}

/// The AI client. Cheap to clone (wraps an `Arc`).
#[derive(Clone)]
pub struct AiClient {
    /// Trimmed base URL of the AI service.
    base_url: String,
    /// Static bearer token.
    auth_token: Arc<String>,
    http: Sentin8HttpClient,
}

impl AiClient {
    /// Construct a new client.
    ///
    /// - `base_url`: AI server URL (e.g. `sentin8_ai_url()` from
    ///   `sentin8-config`, or `http://localhost:{port}` in dev).
    /// - `auth_token`: bearer token carrying the required
    ///   `sentin8:ai:{resource}:{action}` scope.
    pub fn new(base_url: impl Into<String>, auth_token: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            auth_token: Arc::new(auth_token.into()),
            http: Sentin8HttpClient::new(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// `POST /v1/chat` — chat inference.
    pub async fn chat(&self, req: &InferenceRequest) -> Result<InferenceResponse, AiError> {
        self.post_json("/v1/chat", req).await
    }

    /// `POST /v1/completions` — completion inference.
    pub async fn complete(&self, req: &InferenceRequest) -> Result<InferenceResponse, AiError> {
        self.post_json("/v1/completions", req).await
    }

    /// `POST /v1/embeddings` — batch embeddings (input order preserved).
    pub async fn embed(&self, req: &EmbeddingRequest) -> Result<EmbeddingResponse, AiError> {
        self.post_json("/v1/embeddings", req).await
    }

    /// `POST /v1/retrieval` — hybrid permission-filtered retrieval.
    pub async fn retrieve(&self, req: &RetrievalRequest) -> Result<RetrievalResponse, AiError> {
        self.post_json("/v1/retrieval", req).await
    }

    async fn post_json<B: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<R, AiError> {
        let resp = self
            .http
            .post(self.url(path))
            .bearer_auth(self.auth_token.as_str())
            .json(body)
            .send()
            .await
            .map_err(|e| AiError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let detail = resp.text().await.unwrap_or_default();
            return Err(AiError::Http(format!("status {status}: {detail}")));
        }
        resp.json()
            .await
            .map_err(|e| AiError::Decode(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_shapes_roundtrip() {
        let req = InferenceRequest::from_prompt("customer_reply");
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["prompt_name"], "customer_reply");
        assert_eq!(json["feature"], "default");
        let back: InferenceRequest = serde_json::from_value(json).unwrap();
        assert_eq!(back, req);

        let emb = EmbeddingRequest {
            model: "ollama/nomic-embed-text".into(),
            inputs: vec!["a".into()],
            feature: "rag".into(),
            target_env_id: None,
        };
        let json = serde_json::to_value(&emb).unwrap();
        assert_eq!(json["model"], "ollama/nomic-embed-text");
    }

    #[tokio::test]
    async fn client_chat_roundtrip_against_local_mock() {
        // PQ provider must be installed before any HTTPS-capable client is
        // constructed (testing-strategy; reqwest panics otherwise).
        sentin8_tls::crypto::sentin8_pq_provider()
            .install_default()
            .ok();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let n = stream.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            assert!(req.contains("POST /v1/chat"), "path: {req}");
            // reqwest sends lowercase header names; case-insensitive check
            // (memory note: assert case-insensitively in HTTP mock tests).
            let lower = req.to_ascii_lowercase();
            assert!(
                lower.contains("authorization: bearer ai-token"),
                "auth: {req}"
            );
            let body = r#"{"content":"ok","model":"gpt-test","input_tokens":1,"output_tokens":1,"latency_ms":3,"cache_hit":false,"idempotent_replay":false}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(resp.as_bytes()).await.unwrap();
        });
        let client = AiClient::new(format!("http://{addr}"), "ai-token");
        let resp = client
            .chat(&InferenceRequest::complete("openai/gpt-test", "hi"))
            .await
            .unwrap();
        assert_eq!(resp.content, "ok");
        assert!(!resp.cache_hit);
        server.await.unwrap();
    }
}
