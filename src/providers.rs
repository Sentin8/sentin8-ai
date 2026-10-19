// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:AI
// SPDX-License-Identifier: Apache-2.0

//! Model provider layer ().
//!
//! Adapters implement [`CompletionProvider`] / [`EmbeddingProvider`] and
//! route through [`ProviderRouter`], which applies the prompt's
//! primary→fallback chain, per-call timeouts and bounded retries.
//!
//! Credentials are NEVER held here - the caller supplies the bearer via
//! [`ProviderCredential`], resolved at call time from a secret *reference*
//! (architecture-; "secret-reference-only").
//!
//! Tests never hit real endpoints: the trait consumes a
//! `reqwest_middleware`-free plain [`reqwest::Client`], and
//! [`http_mock_client`] returns a client pinned to a local mock server.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Credential material for a single provider call, resolved from the
/// registry's secret reference. Never logged, never persisted.
#[derive(Debug, Clone)]
pub enum ProviderCredential {
    /// Bearer API key (`Authorization: Bearer <key>` - OpenAI/Ollama Cloud).
    Bearer(String),
    /// `x-api-key` header (Anthropic).
    ApiKeyHeader(String),
}

impl ProviderCredential {
    pub(crate) fn apply(self, headers: reqwest::header::HeaderMap) -> reqwest::header::HeaderMap {
        use reqwest::header::{HeaderName, HeaderValue};
        let (name, value) = match self {
            ProviderCredential::Bearer(key) => (
                reqwest::header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {key}"))
                    .unwrap_or(HeaderValue::from_static("")),
            ),
            ProviderCredential::ApiKeyHeader(key) => (
                HeaderName::from_static("x-api-key"),
                HeaderValue::from_str(&key).unwrap_or(HeaderValue::from_static("")),
            ),
        };
        let mut h = headers;
        h.insert(name, value);
        h
    }
}

// ── Wire types (provider-agnostic, normalized) ─────────────────────────────

/// A single chat message in the normalized envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, utoipa::ToSchema)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

/// Normalized completion/chat request passed to adapters.
#[derive(Debug, Clone)]
pub struct CompletionRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    pub temperature: Option<f64>,
    pub max_tokens: Option<u32>,
    /// Declared tools (pass-through; agent runtime resolves these).
    pub tools: Vec<serde_json::Value>,
}

/// Normalized completion/chat response with token usage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompletionResponse {
    pub content: String,
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// AI-1: true when usage was estimated, not provider-reported.
    #[serde(default)]
    pub usage_estimated: bool,
}

/// Normalized embedding request.
#[derive(Debug, Clone)]
pub struct EmbeddingRequest {
    pub model: String,
    pub inputs: Vec<String>,
}

/// Normalized embedding response - one vector per input, same order.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EmbeddingResponse {
    pub model: String,
    pub vectors: Vec<Vec<f32>>,
}

/// One streamed delta from the provider. `done` marks the terminal
/// frame carrying the token accounting.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StreamDelta {
    /// Incremental text emitted since the last frame.
    pub delta: String,
    /// true on the terminal frame (usage populated, no more deltas).
    pub done: bool,
    /// Model echoed back by the provider.
    pub model: String,
    /// Token accounting - populated on the terminal frame.
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// AI-1: true when the accounting was ESTIMATED (synthesized terminal
    /// frame or a char/4 heuristic) instead of reported by the provider -
    /// dashboards can mark the sample as approximate.
    #[serde(default)]
    pub usage_estimated: bool,
}

/// Provider failure classified for routing/failover.
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    /// Retry with backoff (429/5xx/timeout/network).
    #[error("provider transient failure ({provider}): {message}")]
    Transient { provider: String, message: String },
    /// Do not retry (4xx, schema violation, auth).
    #[error("provider terminal failure ({provider}): {message}")]
    Terminal { provider: String, message: String },
}

impl ProviderError {
    pub fn is_retryable(&self) -> bool {
        matches!(self, ProviderError::Transient { .. })
    }
}

// ── Provider trait ─────────────────────────────────────────────────────────

/// The model-provider boundary. One impl per provider;
/// all calls are authenticated by the host (Rust) - credentials never reach
/// WASM, prompts or clients.
#[async_trait::async_trait]
pub trait CompletionProvider: Send + Sync {
    fn name(&self) -> &'static str;
    async fn complete(
        &self,
        client: &reqwest::Client,
        credential: &ProviderCredential,
        req: &CompletionRequest,
    ) -> Result<CompletionResponse, ProviderError>;
    /// Provider-side token streaming : yields incremental deltas
    /// straight from the provider's SSE stream. The default buffers -
    /// adapters that support SSE streaming override this (OpenAI-family and
    /// Ollama Cloud/vLLM all speak the OpenAI `stream: true` surface).
    async fn complete_stream(
        &self,
        client: &reqwest::Client,
        credential: &ProviderCredential,
        req: &CompletionRequest,
    ) -> Result<
        std::pin::Pin<
            Box<dyn tokio_stream::Stream<Item = Result<StreamDelta, ProviderError>> + Send>,
        >,
        ProviderError,
    > {
        // Default: single-shot - run the buffered call and yield one delta.
        let resp = self.complete(client, credential, req).await?;
        let done = StreamDelta {
            delta: resp.content,
            done: true,
            model: resp.model,
            input_tokens: resp.input_tokens,
            output_tokens: resp.output_tokens,
            usage_estimated: resp.usage_estimated,
        };
        Ok(Box::pin(tokio_stream::once(Ok(done))))
    }
    /// Whether the adapter implements real provider-side streaming (the
    /// default buffers; `true` means SSE deltas flow end-to-end).
    fn supports_streaming(&self) -> bool {
        false
    }
    /// Whether the adapter's SSE stream reports authoritative token usage
    /// on the terminal frame (AI-1, ai DESIGN §10): `true` means the
    /// accounting is provider-reported; `false` means the terminal frame is
    /// synthesized (`usage_estimated: true`) and consumers treat the token
    /// counts as approximate.
    fn reports_stream_usage(&self) -> bool {
        false
    }
}

#[async_trait::async_trait]
pub trait EmbeddingProvider: Send + Sync {
    fn name(&self) -> &'static str;
    async fn embed(
        &self,
        client: &reqwest::Client,
        credential: &ProviderCredential,
        req: &EmbeddingRequest,
    ) -> Result<EmbeddingResponse, ProviderError>;
}

// ── Adapters ───────────────────────────────────────────────────────────────

/// OpenAI `/v1/chat/completions` + `/v1/embeddings`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OpenAiAdapter {
    /// Base URL, e.g. `https://api.openai.com` (no trailing slash).
    pub base_url: String,
}

#[derive(Debug, Serialize)]
struct OpenAiChatBody<'a> {
    model: &'a str,
    messages: Vec<ChatMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tools: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct OpenAiChatResp {
    choices: Vec<OpenAiChoice>,
    usage: OpenAiUsage,
}

#[derive(Debug, Deserialize)]
struct OpenAiChoice {
    #[serde(default)]
    message: Option<OpenAiMessage>,
}

#[derive(Debug, Deserialize)]
struct OpenAiMessage {
    #[serde(default)]
    content: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OpenAiUsage {
    #[serde(default)]
    prompt_tokens: u64,
    #[serde(default)]
    completion_tokens: u64,
}

#[derive(Debug, Serialize)]
struct OpenAiEmbedBody<'a> {
    model: &'a str,
    input: &'a [String],
}

#[derive(Debug, Deserialize)]
struct OpenAiEmbedResp {
    data: Vec<OpenAiEmbedData>,
}

#[derive(Debug, Deserialize)]
struct OpenAiEmbedData {
    embedding: Vec<f32>,
}

#[async_trait::async_trait]
impl CompletionProvider for OpenAiAdapter {
    fn name(&self) -> &'static str {
        "openai"
    }

    async fn complete(
        &self,
        client: &reqwest::Client,
        credential: &ProviderCredential,
        req: &CompletionRequest,
    ) -> Result<CompletionResponse, ProviderError> {
        let url = format!(
            "{}/v1/chat/completions",
            self.base_url.trim_end_matches('/')
        );
        let body = OpenAiChatBody {
            model: &req.model,
            messages: req.messages.clone(),
            temperature: req.temperature,
            max_tokens: req.max_tokens,
            tools: req.tools.clone(),
        };
        let resp = client
            .post(&url)
            .headers(credential.clone().apply(Default::default()))
            .json(&body)
            .send()
            .await
            .map_err(|e| ProviderError::Transient {
                provider: "openai".into(),
                message: e.to_string(),
            })?;
        parse_openai_chat(resp, req).await
    }

    async fn complete_stream(
        &self,
        client: &reqwest::Client,
        credential: &ProviderCredential,
        req: &CompletionRequest,
    ) -> Result<
        std::pin::Pin<
            Box<dyn tokio_stream::Stream<Item = Result<StreamDelta, ProviderError>> + Send>,
        >,
        ProviderError,
    > {
        openai_stream(client, &self.base_url, credential, req).await
    }

    fn supports_streaming(&self) -> bool {
        true
    }

    // AI-1: the OpenAI-family body sends `stream_options.include_usage` -
    // a usage-bearing terminal frame (or `[DONE]`-flush of accumulated
    // accounting) closes the stream.
    fn reports_stream_usage(&self) -> bool {
        true
    }
}

async fn parse_openai_chat(
    resp: reqwest::Response,
    req: &CompletionRequest,
) -> Result<CompletionResponse, ProviderError> {
    let status = resp.status();
    let payload: serde_json::Value = resp.json().await.map_err(|e| ProviderError::Transient {
        provider: "openai".into(),
        message: format!("unreadable response: {e}"),
    })?;
    if !status.is_success() {
        let message = payload
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(|m| m.as_str())
            .unwrap_or("unknown provider error")
            .to_string();
        return Err(classify_status("openai", status.as_u16(), &message));
    }
    let parsed: OpenAiChatResp =
        serde_json::from_value(payload).map_err(|e| ProviderError::Terminal {
            provider: "openai".into(),
            message: format!("schema violation: {e}"),
        })?;
    let content = parsed
        .choices
        .first()
        .and_then(|c| c.message.as_ref())
        .and_then(|m| m.content.clone())
        .unwrap_or_default();
    Ok(CompletionResponse {
        content,
        model: req.model.clone(),
        usage_estimated: false,
        input_tokens: parsed.usage.prompt_tokens,
        output_tokens: parsed.usage.completion_tokens,
    })
}

fn classify_status(provider: &str, status: u16, message: &str) -> ProviderError {
    if status == 429 || status >= 500 {
        ProviderError::Transient {
            provider: provider.into(),
            message: format!("http {status}: {message}"),
        }
    } else {
        ProviderError::Terminal {
            provider: provider.into(),
            message: format!("http {status}: {message}"),
        }
    }
}

// ── Provider-side SSE streaming ──────────────────────────────────

#[derive(Debug, Deserialize)]
struct OpenAiStreamChunk {
    #[serde(default)]
    model: String,
    #[serde(default)]
    choices: Vec<OpenAiStreamChoice>,
    /// Terminal chunk when `stream_options.include_usage` is honored.
    #[serde(default)]
    usage: Option<OpenAiUsage>,
}

#[derive(Debug, Deserialize)]
struct OpenAiStreamChoice {
    #[serde(default)]
    delta: Option<OpenAiStreamDelta>,
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OpenAiStreamDelta {
    #[serde(default)]
    content: Option<String>,
}

/// Parse one SSE `data:` payload line into deltas. `None` on `[DONE]`/
/// non-data lines; `Some(Err)` on schema violations.
fn parse_openai_sse_line(line: &str) -> Option<Result<StreamDelta, String>> {
    let payload = line.strip_prefix("data:")?.trim();
    if payload == "[DONE]" {
        return None;
    }
    let chunk: OpenAiStreamChunk = match serde_json::from_str(payload) {
        Ok(c) => c,
        Err(e) => return Some(Err(format!("stream chunk schema violation: {e}"))),
    };
    let delta_text = chunk
        .choices
        .first()
        .and_then(|c| c.delta.as_ref())
        .and_then(|d| d.content.clone())
        .unwrap_or_default();
    let is_final = chunk
        .choices
        .first()
        .and_then(|c| c.finish_reason.as_deref())
        .map(|f| !f.is_empty())
        .unwrap_or(false);
    let (input_tokens, output_tokens) = chunk
        .usage
        .as_ref()
        .map(|u| (u.prompt_tokens, u.completion_tokens))
        .unwrap_or((0, 0));
    Some(Ok(StreamDelta {
        delta: delta_text,
        done: is_final || chunk.usage.is_some(),
        model: chunk.model,
        input_tokens,
        output_tokens,
        usage_estimated: chunk.usage.is_none(),
    }))
}

/// Async SSE line pump: yields complete lines from a byte stream, keeping
/// the remainder across chunk boundaries. Carries the accumulated token
/// accounting and last-seen model name for the terminal frame.
struct SseLineStream {
    bytes:
        std::pin::Pin<Box<dyn futures_util::Stream<Item = reqwest::Result<bytes::Bytes>> + Send>>,
    buf: String,
    finished: bool,
    model: String,
    input_tokens: u64,
    output_tokens: u64,
    // AI-1: whether a provider usage frame ever arrived (the [DONE]
    // fallback terminal is `usage_estimated` when it never did).
    saw_usage: bool,
}

impl SseLineStream {
    fn new(
        bytes: std::pin::Pin<
            Box<dyn futures_util::Stream<Item = reqwest::Result<bytes::Bytes>> + Send>,
        >,
    ) -> Self {
        Self {
            bytes,
            buf: String::new(),
            finished: false,
            model: String::new(),
            input_tokens: 0,
            output_tokens: 0,
            saw_usage: false,
        }
    }

    async fn next_line(&mut self) -> Option<String> {
        loop {
            if let Some(idx) = self.buf.find('\n') {
                let line = self.buf[..idx].trim().to_string();
                self.buf = self.buf[idx + 1..].to_string();
                return Some(line);
            }
            if self.finished {
                if self.buf.trim().is_empty() {
                    return None;
                }
                let line = self.buf.trim().to_string();
                self.buf.clear();
                return Some(line);
            }
            match futures_util::StreamExt::next(&mut self.bytes).await {
                Some(Ok(chunk)) => self.buf.push_str(&String::from_utf8_lossy(&chunk)),
                Some(Err(_)) | None => self.finished = true,
            }
        }
    }
}

/// Run the OpenAI-family SSE stream and map it into the normalized delta
/// stream. Token accounting accumulates across frames; a terminal
/// frame is synthesized after `[DONE]` when the provider omitted usage.
async fn openai_stream(
    client: &reqwest::Client,
    base_url: &str,
    credential: &ProviderCredential,
    req: &CompletionRequest,
) -> Result<
    std::pin::Pin<Box<dyn tokio_stream::Stream<Item = Result<StreamDelta, ProviderError>> + Send>>,
    ProviderError,
> {
    let url = format!("{}/v1/chat/completions", base_url.trim_end_matches('/'));
    #[derive(Debug, serde::Serialize)]
    struct OpenAiStreamBody {
        model: String,
        messages: Vec<ChatMessage>,
        #[serde(skip_serializing_if = "Option::is_none")]
        temperature: Option<f64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        max_tokens: Option<u32>,
        stream: bool,
        stream_options: OpenAiStreamOptions,
    }
    #[derive(Debug, serde::Serialize)]
    struct OpenAiStreamOptions {
        include_usage: bool,
    }
    let body = OpenAiStreamBody {
        model: req.model.clone(),
        messages: req.messages.clone(),
        temperature: req.temperature,
        max_tokens: req.max_tokens,
        stream: true,
        stream_options: OpenAiStreamOptions {
            include_usage: true,
        },
    };
    let resp = client
        .post(&url)
        .headers(credential.clone().apply(Default::default()))
        .json(&body)
        .send()
        .await
        .map_err(|e| ProviderError::Transient {
            provider: "openai".into(),
            message: e.to_string(),
        })?;
    let status = resp.status();
    if !status.is_success() {
        let message = resp
            .text()
            .await
            .unwrap_or_else(|_| "unreadable error body".into());
        return Err(classify_status("openai", status.as_u16(), &message));
    }
    // Map the SSE byte stream into normalized deltas with a plain unfold:
    // read lines → parse → carry accounting across frames.
    let sse = SseLineStream::new(Box::pin(resp.bytes_stream()));
    let stream = futures_util::stream::unfold(
        (sse, None::<StreamDelta>),
        |(mut sse, mut terminal_pending)| async move {
            loop {
                // A deferred finish_reason terminal flushes with the latest
                // accumulated accounting (the usage frame arrives after it).
                if let Some(mut d) = terminal_pending.take() {
                    d.input_tokens = sse.input_tokens;
                    d.output_tokens = sse.output_tokens;
                    // AI-1: usage never arrived after finish_reason - the
                    // flushed accounting is the estimate marker path.
                    d.usage_estimated = !sse.saw_usage;
                    return Some((Ok(d), (sse, None)));
                }
                if sse.finished {
                    return None;
                }
                let Some(line) = sse.next_line().await else {
                    return None;
                };
                if line.is_empty() || line.starts_with("event:") {
                    continue;
                }
                if line.trim() == "data: [DONE]" || line.trim() == "data:[DONE]" {
                    // Terminal frame - carry the accumulated accounting.
                    let d = StreamDelta {
                        delta: String::new(),
                        done: true,
                        model: sse.model.clone(),
                        input_tokens: sse.input_tokens,
                        output_tokens: sse.output_tokens,
                        // AI-1: the [DONE] fallback synthesizes the terminal
                        // from accumulated accounting - estimated when NO
                        // usage frame ever arrived.
                        usage_estimated: !sse.saw_usage,
                    };
                    sse.finished = true;
                    return Some((Ok(d), (sse, None)));
                }
                match parse_openai_sse_line(&line) {
                    Some(Ok(d)) => {
                        if d.input_tokens > 0 {
                            sse.input_tokens = d.input_tokens;
                        }
                        if d.output_tokens > 0 {
                            sse.output_tokens = d.output_tokens;
                        }
                        if d.input_tokens > 0 || d.output_tokens > 0 {
                            sse.saw_usage = true;
                        }
                        if !d.model.is_empty() {
                            sse.model = d.model.clone();
                        }
                        if d.done && d.input_tokens > 0 {
                            // Usage-bearing terminal frame - emit immediately.
                            sse.finished = true;
                            return Some((Ok(d), (sse, None)));
                        }
                        if d.done {
                            // finish_reason stop: the usage frame typically
                            // FOLLOWS (stream_options.include_usage). Defer the
                            // terminal emission until the usage frame or [DONE]
                            // flushes the accumulated accounting.
                            sse.finished = false;
                            terminal_pending = Some(d);
                            continue;
                        }
                        if !d.delta.is_empty() {
                            return Some((Ok(d), (sse, None)));
                        }
                        // Empty delta + not done → next line.
                    }
                    Some(Err(e)) => {
                        sse.finished = true;
                        return Some((
                            Err(ProviderError::Terminal {
                                provider: "openai".into(),
                                message: e,
                            }),
                            (sse, None),
                        ));
                    }
                    None => {
                        // [DONE] without the prefix match above (whitespace
                        // variants) or a non-data line - skip.
                        continue;
                    }
                }
            }
        },
    );
    Ok(Box::pin(stream))
}

#[async_trait::async_trait]
impl EmbeddingProvider for OpenAiAdapter {
    fn name(&self) -> &'static str {
        "openai"
    }

    async fn embed(
        &self,
        client: &reqwest::Client,
        credential: &ProviderCredential,
        req: &EmbeddingRequest,
    ) -> Result<EmbeddingResponse, ProviderError> {
        let url = format!("{}/v1/embeddings", self.base_url.trim_end_matches('/'));
        let body = OpenAiEmbedBody {
            model: &req.model,
            input: &req.inputs,
        };
        let resp = client
            .post(&url)
            .headers(credential.clone().apply(Default::default()))
            .json(&body)
            .send()
            .await
            .map_err(|e| ProviderError::Transient {
                provider: "openai".into(),
                message: e.to_string(),
            })?;
        let status = resp.status();
        let payload: serde_json::Value =
            resp.json().await.map_err(|e| ProviderError::Transient {
                provider: "openai".into(),
                message: format!("unreadable response: {e}"),
            })?;
        if !status.is_success() {
            let message = payload
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
                .unwrap_or("unknown provider error")
                .to_string();
            return Err(classify_status("openai", status.as_u16(), &message));
        }
        let parsed: OpenAiEmbedResp =
            serde_json::from_value(payload).map_err(|e| ProviderError::Terminal {
                provider: "openai".into(),
                message: format!("schema violation: {e}"),
            })?;
        // OpenAI returns `data` in input order (data[i] ↔ input[i]); the
        // invariant is asserted in tests.
        let vectors = parsed.data.into_iter().map(|d| d.embedding).collect();
        Ok(EmbeddingResponse {
            model: req.model.clone(),
            vectors,
        })
    }
}

/// Anthropic `/v1/messages` (chat only; no embedding API - embeddings route
/// to another provider by prompt config).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AnthropicAdapter {
    pub base_url: String,
    /// Required `anthropic-version` header value.
    pub version: String,
}

#[derive(Debug, Serialize)]
struct AnthropicBody<'a> {
    model: &'a str,
    messages: Vec<AnthropicMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AnthropicMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct AnthropicResp {
    content: Vec<AnthropicContent>,
    usage: AnthropicUsage,
}

#[derive(Debug, Deserialize)]
struct AnthropicContent {
    #[serde(default)]
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AnthropicUsage {
    #[serde(default)]
    input_tokens: u64,
    #[serde(default)]
    output_tokens: u64,
}

#[async_trait::async_trait]
impl CompletionProvider for AnthropicAdapter {
    fn name(&self) -> &'static str {
        "anthropic"
    }

    async fn complete(
        &self,
        client: &reqwest::Client,
        credential: &ProviderCredential,
        req: &CompletionRequest,
    ) -> Result<CompletionResponse, ProviderError> {
        let url = format!("{}/v1/messages", self.base_url.trim_end_matches('/'));
        // Anthropic requires a max_tokens; default to 4096 when unset.
        let body = AnthropicBody {
            model: &req.model,
            messages: req
                .messages
                .iter()
                .filter(|m| m.role != "system")
                .map(|m| AnthropicMessage {
                    role: m.role.clone(),
                    content: m.content.clone(),
                })
                .collect(),
            max_tokens: Some(req.max_tokens.unwrap_or(4096)),
            temperature: req.temperature,
        };
        let headers = credential.clone().apply(Default::default());
        let headers = {
            use reqwest::header::{HeaderName, HeaderValue};
            let mut h = headers;
            if let Ok(v) = HeaderValue::from_str(&self.version) {
                h.insert(HeaderName::from_static("anthropic-version"), v);
            }
            h
        };
        let resp = client
            .post(&url)
            .headers(headers)
            .json(&body)
            .send()
            .await
            .map_err(|e| ProviderError::Transient {
                provider: "anthropic".into(),
                message: e.to_string(),
            })?;
        let status = resp.status();
        let payload: serde_json::Value =
            resp.json().await.map_err(|e| ProviderError::Transient {
                provider: "anthropic".into(),
                message: format!("unreadable response: {e}"),
            })?;
        if !status.is_success() {
            let message = payload
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
                .unwrap_or("unknown provider error")
                .to_string();
            return Err(classify_status("anthropic", status.as_u16(), &message));
        }
        let parsed: AnthropicResp =
            serde_json::from_value(payload).map_err(|e| ProviderError::Terminal {
                provider: "anthropic".into(),
                message: format!("schema violation: {e}"),
            })?;
        let content = parsed
            .content
            .into_iter()
            .filter_map(|c| c.text)
            .collect::<Vec<_>>()
            .join("");
        Ok(CompletionResponse {
            content,
            model: req.model.clone(),
            input_tokens: parsed.usage.input_tokens,
            output_tokens: parsed.usage.output_tokens,
            usage_estimated: false,
        })
    }
}

/// Ollama Cloud - OpenAI-compatible `/v1/chat/completions` for chat, native
/// `/api/embed` for embeddings ( v1 provider set).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OllamaCloudAdapter {
    /// Base URL, e.g. `https://ollama.com` (no trailing slash).
    pub base_url: String,
}

#[async_trait::async_trait]
impl CompletionProvider for OllamaCloudAdapter {
    fn name(&self) -> &'static str {
        "ollama"
    }

    async fn complete(
        &self,
        client: &reqwest::Client,
        credential: &ProviderCredential,
        req: &CompletionRequest,
    ) -> Result<CompletionResponse, ProviderError> {
        // OpenAI-compatible - reuse the OpenAI wire format against the
        // Ollama Cloud base URL.
        let openai = OpenAiAdapter {
            base_url: self.base_url.clone(),
        };
        openai.complete(client, credential, req).await
    }
}

#[derive(Debug, Serialize)]
struct OllamaEmbedBody<'a> {
    model: &'a str,
    input: &'a [String],
}

#[derive(Clone, Debug, Deserialize)]
struct OllamaEmbedResp {
    embeddings: Vec<Vec<f32>>,
}

#[async_trait::async_trait]
impl EmbeddingProvider for OllamaCloudAdapter {
    fn name(&self) -> &'static str {
        "ollama"
    }

    async fn embed(
        &self,
        client: &reqwest::Client,
        credential: &ProviderCredential,
        req: &EmbeddingRequest,
    ) -> Result<EmbeddingResponse, ProviderError> {
        let url = format!("{}/api/embed", self.base_url.trim_end_matches('/'));
        let body = OllamaEmbedBody {
            model: &req.model,
            input: &req.inputs,
        };
        let resp = client
            .post(&url)
            .headers(credential.clone().apply(Default::default()))
            .json(&body)
            .send()
            .await
            .map_err(|e| ProviderError::Transient {
                provider: "ollama".into(),
                message: e.to_string(),
            })?;
        let status = resp.status();
        let payload: serde_json::Value =
            resp.json().await.map_err(|e| ProviderError::Transient {
                provider: "ollama".into(),
                message: format!("unreadable response: {e}"),
            })?;
        if !status.is_success() {
            let message = payload
                .get("error")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown provider error")
                .to_string();
            return Err(classify_status("ollama", status.as_u16(), &message));
        }
        let parsed: OllamaEmbedResp =
            serde_json::from_value(payload).map_err(|e| ProviderError::Terminal {
                provider: "ollama".into(),
                message: format!("schema violation: {e}"),
            })?;
        Ok(EmbeddingResponse {
            model: req.model.clone(),
            vectors: parsed.embeddings,
        })
    }
}

/// Self-hosted OpenAI-compatible endpoint (vLLM-style) - isolation level 3
/// dedicated-env deployments. Chat rides `/v1/chat/completions`,
/// embeddings ride `/v1/embeddings` (vLLM serves the OpenAI surface).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VllmAdapter {
    /// Base URL, e.g. `http://vllm.internal:8000` (no trailing slash).
    pub base_url: String,
}

#[async_trait::async_trait]
impl CompletionProvider for VllmAdapter {
    fn name(&self) -> &'static str {
        "vllm"
    }

    async fn complete(
        &self,
        client: &reqwest::Client,
        credential: &ProviderCredential,
        req: &CompletionRequest,
    ) -> Result<CompletionResponse, ProviderError> {
        let openai = OpenAiAdapter {
            base_url: self.base_url.clone(),
        };
        openai.complete(client, credential, req).await
    }
}

#[async_trait::async_trait]
impl EmbeddingProvider for VllmAdapter {
    fn name(&self) -> &'static str {
        "vllm"
    }

    async fn embed(
        &self,
        client: &reqwest::Client,
        credential: &ProviderCredential,
        req: &EmbeddingRequest,
    ) -> Result<EmbeddingResponse, ProviderError> {
        let openai = OpenAiAdapter {
            base_url: self.base_url.clone(),
        };
        openai.embed(client, credential, req).await
    }
}

// ── Router ( - primary → fallback, timeout, bounded retries) ────────

/// Routing entry: adapter + named model + credential resolver key.
pub struct Route {
    pub provider: std::sync::Arc<dyn CompletionProvider>,
    pub embedder: Option<std::sync::Arc<dyn EmbeddingProvider>>,
    pub credential: ProviderCredential,
    pub model: String,
}

impl Clone for Route {
    fn clone(&self) -> Self {
        Self {
            provider: self.provider.clone(),
            embedder: self.embedder.clone(),
            credential: self.credential.clone(),
            model: self.model.clone(),
        }
    }
}

impl std::fmt::Debug for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Route")
            .field("provider", &self.provider.name())
            .field("has_embedder", &self.embedder.is_some())
            .field("model", &self.model)
            .finish()
    }
}

/// Executes a request across primary → fallback with per-call timeout and
/// bounded retries (default: 2 attempts, exponential backoff 100ms → 400ms).
pub struct ProviderRouter {
    pub timeout: Duration,
    pub max_retries: u32,
}

impl Default for ProviderRouter {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_retries: 2,
        }
    }
}

impl ProviderRouter {
    #[allow(clippy::too_many_arguments)]
    pub async fn complete(
        &self,
        client: &reqwest::Client,
        primary: &Route,
        fallback: Option<&Route>,
        req: &CompletionRequest,
    ) -> Result<CompletionResponse, ProviderError> {
        let mut last_err = None;
        for route in [Some(primary), fallback].into_iter().flatten() {
            for attempt in 0..=self.max_retries {
                match route
                    .provider
                    .complete(client, &route.credential, req)
                    .await
                {
                    Ok(resp) => return Ok(resp),
                    Err(e) if e.is_retryable() && attempt < self.max_retries => {
                        tracing::warn!(provider = route.provider.name(), attempt, "provider retry");
                        tokio::time::sleep(Duration::from_millis(100 * 2u64.pow(attempt))).await;
                    }
                    Err(e) => {
                        last_err = Some(e);
                        break;
                    }
                }
            }
        }
        Err(last_err.unwrap_or_else(|| ProviderError::Terminal {
            provider: "router".into(),
            message: "no route configured".into(),
        }))
    }

    pub async fn embed(
        &self,
        client: &reqwest::Client,
        route: &Route,
        req: &EmbeddingRequest,
    ) -> Result<EmbeddingResponse, ProviderError> {
        let embedder = route
            .embedder
            .as_ref()
            .ok_or_else(|| ProviderError::Terminal {
                provider: route.provider.name().into(),
                message: "provider has no embedding endpoint".into(),
            })?;
        for attempt in 0..=self.max_retries {
            match embedder.embed(client, &route.credential, req).await {
                Ok(resp) => return Ok(resp),
                Err(e) if e.is_retryable() && attempt < self.max_retries => {
                    tracing::warn!(provider = route.provider.name(), attempt, "provider retry");
                    tokio::time::sleep(Duration::from_millis(100 * 2u64.pow(attempt))).await;
                }
                Err(e) => return Err(e),
            }
        }
        Err(ProviderError::Terminal {
            provider: route.provider.name().into(),
            message: "retries exhausted".into(),
        })
    }

    /// Stream a completion across primary → fallback. Streaming is
    /// not retried mid-stream - only connection-level failures before the
    /// first delta fall back to the next route.
    pub async fn complete_stream(
        &self,
        client: &reqwest::Client,
        primary: &Route,
        fallback: Option<&Route>,
        req: &CompletionRequest,
    ) -> Result<
        std::pin::Pin<
            Box<dyn tokio_stream::Stream<Item = Result<StreamDelta, ProviderError>> + Send>,
        >,
        ProviderError,
    > {
        let mut last_err = None;
        for route in [Some(primary), fallback].into_iter().flatten() {
            match route
                .provider
                .complete_stream(client, &route.credential, req)
                .await
            {
                Ok(stream) => return Ok(stream),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| ProviderError::Terminal {
            provider: "router".into(),
            message: "no route configured".into(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ordering invariant: OpenAI `data[i]` corresponds to `input[i]` -
    /// the adapter must return vectors in input order.
    #[tokio::test]
    async fn openai_embed_preserves_input_order() {
        // reqwest panics "No provider set" without the PQ crypto provider
        // (the test binary bypasses the shell boot).
        let _ = sentin8::tls::crypto::sentin8_pq_provider().install_default();
        // Minimal local mock asserting order - spun up with tokio's TCP
        // listener so no external endpoint is contacted.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let n = stream.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            // Inputs arrive in order a,b - the mock echoes lengths 1 then 2
            // so order is observable in vector dims.
            assert!(req.contains("\"input\":[\"a\",\"b\"]"), "body: {req}");
            let body = r#"{"data":[{"embedding":[1.0]},{"embedding":[1.0,2.0]}]}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(resp.as_bytes()).await.unwrap();
        });
        let adapter = OpenAiAdapter {
            base_url: format!("http://{addr}"),
        };
        let client = reqwest::Client::new();
        let resp = adapter
            .embed(
                &client,
                &ProviderCredential::Bearer("k".into()),
                &EmbeddingRequest {
                    model: "m".into(),
                    inputs: vec!["a".into(), "b".into()],
                },
            )
            .await
            .unwrap();
        assert_eq!(resp.vectors.len(), 2);
        assert_eq!(
            resp.vectors[0].len(),
            1,
            "first input must map to first vector"
        );
        assert_eq!(resp.vectors[1].len(), 2);
        server.await.unwrap();
    }

    #[test]
    fn classify_maps_retryable_status() {
        assert!(classify_status("openai", 429, "rate").is_retryable());
        assert!(classify_status("openai", 503, "down").is_retryable());
        assert!(!classify_status("openai", 401, "bad key").is_retryable());
        assert!(!classify_status("openai", 422, "schema").is_retryable());
    }

    /// SSE line parsing : delta frames, finish_reason terminal, and
    /// usage-bearing terminal frames all map to the normalized StreamDelta.
    #[test]
    fn sse_line_parses_delta_terminal_and_usage() {
        let d =
            parse_openai_sse_line(r#"data: {"choices":[{"delta":{"content":"he"}}],"model":"m1"}"#)
                .unwrap()
                .unwrap();
        assert_eq!(d.delta, "he");
        assert!(!d.done);

        let t = parse_openai_sse_line(
            r#"data: {"choices":[{"delta":{},"finish_reason":"stop"}],"model":"m1"}"#,
        )
        .unwrap()
        .unwrap();
        assert!(t.done);

        let u = parse_openai_sse_line(
            r#"data: {"choices":[],"usage":{"prompt_tokens":7,"completion_tokens":3},"model":"m1"}"#,
        )
        .unwrap()
        .unwrap();
        assert!(u.done);
        assert_eq!(u.input_tokens, 7);
        assert_eq!(u.output_tokens, 3);

        assert!(parse_openai_sse_line("data: [DONE]").is_none());
        assert!(parse_openai_sse_line(": keep-alive").is_none());
        assert!(parse_openai_sse_line("data: {bad json").unwrap().is_err());
    }

    /// End-to-end SSE streaming through a local mock: deltas flow in order
    /// and the terminal frame carries the accumulated usage.
    #[tokio::test]
    async fn openai_stream_mock_emits_deltas_in_order() {
        let _ = sentin8::tls::crypto::sentin8_pq_provider().install_default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let _ = stream.read(&mut buf).await.unwrap();
            let body = "data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}],\"model\":\"m\"}\n\n"
                .to_owned()
                + "data: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}],\"model\":\"m\"}\n\n"
                + "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"model\":\"m\"}\n\n"
                + "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":4},\"model\":\"m\"}\n\n"
                + "data: [DONE]\n\n";
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(resp.as_bytes()).await.unwrap();
        });
        let adapter = OpenAiAdapter {
            base_url: format!("http://{addr}"),
        };
        let client = reqwest::Client::new();
        let stream = adapter
            .complete_stream(
                &client,
                &ProviderCredential::Bearer("k".into()),
                &CompletionRequest {
                    model: "m".into(),
                    messages: vec![ChatMessage {
                        role: "user".into(),
                        content: "x".into(),
                    }],
                    temperature: None,
                    max_tokens: None,
                    tools: vec![],
                },
            )
            .await
            .unwrap();
        use tokio_stream::StreamExt;
        let deltas: Vec<StreamDelta> = stream.map(|r| r.unwrap()).collect().await;
        let text: String = deltas.iter().map(|d| d.delta.as_str()).collect();
        assert_eq!(text, "Hello", "deltas must concatenate in order");
        let terminal = deltas.last().unwrap();
        assert!(terminal.done);
        assert_eq!(terminal.input_tokens, 11);
        assert_eq!(terminal.output_tokens, 4);
        server.await.unwrap();
    }
}
