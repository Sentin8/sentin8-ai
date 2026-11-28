# Sentin8:AI - Business Requirements & Functionality

> Audience: product owners, business analysts, and anyone evaluating what
> Sentin8:AI **does for the business**. For architecture read `README.md`;
> for wire-level detail read `DESIGN.md`.

## 1. Business Purpose

Sentin8:AI is the platform's **AI capability layer**. It gives every
vertical and app a single, governed AI surface - completions, chat,
embeddings, retrieval, and a **multi-turn agent runtime** - without any of
them embedding their own model-vendor SDKs or safety stacks. The business
value it delivers:

- **One AI surface for every vertical.** Verticals need completions, chat,
  embeddings, and retrieval without each embedding an SDK stack; the
  service centralizes the prompt lifecycle, provider routing, safety
  filtering, cost accounting, and audit behind one Shield-gated API.
- **Providers change; contracts don't.** Model vendors and their APIs
  churn (OpenAI, Anthropic, Ollama Cloud/Hosted, vLLM, future providers);
  the adapter boundary isolates that churn behind two traits while the rest
  of the platform codes against prompt id + inference request/response.
- **Agents that reason and act, safely.** A conversation keeps its history,
  the model calls declared tools, and it sees the results - a real
  multi-turn agent. Every action passes one gateway that validates
  arguments, checks the caller's permissions, and pauses irreversible work
  for human approval. The model never executes; the caller's authority
  always decides.
- **Every edge function can use a model.** A Sentin8:Func module calls a
  model through one host function with its own identity and a narrow
  inference scope - no bespoke integration per service.
- **Everything is customizable per tenant.** Prompts, providers, tools,
  agents, policies, budgets, filters, and workflows are tenant rows with
  admin surfaces; nothing valuable is a platform constant.
- **Cost must be governed, not just observed.** Token spend is the
  dominant operational risk of AI features; budgets are enforced as a
  pre-call gate (reject or degrade), including inside an agent loop where
  every iteration is charged.

## 2. Business Scope (What the Service Provides)

| Area | Capabilities |
|---|---|
| Prompt registry | Versioned, immutable prompts (create, list, get, retire); named-latest resolution; platform-origin vs tenant-origin separation |
| Inference primitives | Completion, chat (buffered), chat streaming (SSE/ndjson), embeddings - routed over a pluggable provider layer |
| Provider routing | OpenAI, Anthropic, Ollama Cloud/Hosted, vLLM adapters; primary→fallback chains per prompt; per-tenant provider configuration that takes effect immediately |
| Hybrid retrieval | Document ingest (chunk→embed→store), hybrid search (pgvector cosine ∪ keyword index), optional reranker, permission-filtered results |
| Conversations | Persistent multi-turn conversations with ordered messages, owner-scoped visibility, per-conversation token/cost totals, archival and retention |
| Agent runtime | Native tool calling in a bounded loop: model → tool → observation → model, with recorded context plan, enumerable stop reasons, and full transcript |
| Tool registry | Tenant-authored tools (name, description, JSON Schema input, target, required permission, side-effect class, rate limit, timeout, response cap); discovery filtered by the caller's permissions; the per-minute rate limit is enforced at dispatch |
| Agents & policies | Named agents composed from a prompt + tool set + policy; per-env policies bounding models, turns, tokens, tool classes, confirmation classes, and retention |
| Human approval | Irreversible tool actions pause for an explicit decision (`/v1/approvals/{id}/decide`); an APPROVAL then executes the tool under the approver's own permission, records the result in the conversation, and closes the run - approval never skips the safety checks |
| Edge-function inference | Sentin8:Func modules call a model through the `ai_infer` host function with the module's own identity and a narrow inference scope |
| Token budgets | Env-wide + per-feature monthly token caps; reject/degrade/queue enforcement modes; pre-call gating **per loop iteration** |
| Safety & moderation | Input, output, **and tool-result** filter chains (baseline prompt-injection rules + tenant-configurable rules); PII deny-list stripping on persisted payloads |
| Observability | Traces (every inference, attributed to its run), Stat metrics (token/cost/latency/cache), cost rollups and queries, trace retention/archive |
| Evaluations | Synchronous per-test-case inference with assertion checks; score reporting |
| Async AI jobs | Embedding, summary, classification, and document-pipeline jobs consumed from the platform Bus (direct consumers, no Func hop); an inbound event can also open an agent turn |
| Dead-letter queue | Failed-job capture with manual replay (`POST /v1/dlq/{id}/replay`) |
| Admin surfaces | RFW admin UI pages for prompts, providers, traces, budgets, DLQ, evaluations, tools, agents, policies, and approvals; shared Shield policy admin |

### What the service does NOT own (business boundary)

| Out of scope | Owner |
|---|---|
| Model credentials | Stored as secret **references** resolved at call time (Sentin8:Secrets / env backend) - material never lands in application tables |
| Long-running tool side effects | Sentin8:Flow (`flow_workflow` tools) and Sentin8:Func (`func_module` tools); AI dispatches, the owner executes |
| Conversation state inside a sandbox or workflow | AI holds the transcript; modules and workflows address a conversation by id |
| Scheduling | Sentin8:Cron (trace archive + stale re-embedding + model-migration sweeps are cron schedules) |
| Document blobs and archived history | Sentin8:Storage (chunk text, trace archives, retained conversation history) |
| Spend analytics | Sentin8:Stat (metric spend) |
| Identity minting | Sentin8:Auth (AI *requests* per-run agent tokens; it does not issue them itself) |

## 3. Business Capabilities

### 3.1 Prompt Registry

| Capability | Business rule |
|---|---|
| Create prompt | New version per update - versions are immutable; 409 on duplicate `(env_id, name, version)` |
| Latest resolution | "Latest per name" resolves at call time; pinned versions supported |
| Retire (delete) | Platform-origin rows are retired, never hard-deleted; tenant rows may be removed |
| Tool declarations | Prompt rows may carry a JSON-output-mode contract; the authoritative tool set is the tenant tool registry bound to an agent |
| Origin separation | `origin platform` rows are enroll-owned; `tenant` rows are never touched by enroll |

### 3.2 Inference

| Capability | Business rule |
|---|---|
| Completion / chat | `POST /v1/completions`, `POST /v1/chat` - Shield-gated; `target_env_id` REQUIRED (400 if missing - no silent cross-tenant fallback) |
| Streaming chat | `POST /v1/chat/stream` (ndjson/SSE) - accumulated buffer moderated per delta; mid-stream violation aborts with an error frame |
| Idempotency | `Idempotency-Key` honored on completion/chat; a completed response replays for a seen key (24h TTL) |
| Provider routing | Primary→fallback chain per prompt; transient errors (429/5xx/timeout) retry with backoff (max 2) then fall over; terminal errors (4xx/auth/schema) fail fast with 422 |
| Exact-match cache | Deterministic prompts hit a Valkey cache before any provider call; every inference journalled with `cache: "hit"\|"miss"` so provenance is auditable |
| Budget gate | Monthly token caps checked BEFORE the provider call - `reject` → 429, `degrade`/`queue` → cost-labelled traces |
| Output schema enforcement | Non-conforming responses rejected when a prompt declares an output schema |
| Moderation both directions | Input stage before the provider call; output stage before the response returns |
| PII stripping | Same deny-list keys as Stat (`email`, `pan`, `pin`, `ssn`, `token`…) strip persisted payload keys; traces flag when stripping occurred |

### 3.3 Retrieval

| Capability | Business rule |
|---|---|
| Document ingest | Chunk→embed→store pipeline; `POST /v1/documents/ingest` and the Bus `document:uploaded` consumer from ANY vertical |
| Hybrid search | pgvector cosine ∪ keyword (tsvector GIN) union - vector alone misses exact identifiers, keyword alone misses paraphrase |
| Permission-filtered results | Results are filtered by the caller's data scope before return - retrieval never leaks across tenant scopes |
| Reranker | Optional reranker pass |
| Registry | Embedding model registry with version pinning; mismatched embeddings rejected (422) rather than compared across incompatible spaces; model-version stamping on every write with a Cron sweep to re-embed stale rows |

### 3.4 Agents and Conversations

| Capability | Business rule |
|---|---|
| Create conversation | Bound to a named agent; owned by the requesting user; visible only to that user and env admins |
| Send a turn | `POST /v1/conversations/{id}/turns` runs one bounded agent turn and returns the assistant message with a `run_id` and `stop_reason` |
| Multi-turn reasoning | The model sees its own prior messages and every tool result; the next turn is conditioned on the whole recorded history |
| Bounded runs | Every turn stops on a closed set of reasons: `completed`, `max_turns`, `budget`, `cancelled`, `awaiting_approval`, `error` - an agent loop always terminates |
| Tool call validation | Model arguments are validated against the tool's JSON Schema before dispatch; an invalid call is denied with the reason returned to the model |
| Permission check | A tool requires its declared permission over the caller's live permissions; a denied tool is reported to the model and audited, never silently dropped |
| Side-effect classes | `read` and `write` tools execute inline; `irreversible` tools always pause for approval |
| Human approval | `/v1/approvals/{id}/decide` resumes or fails the run; a pending approval past its deadline expires and fails the run |
| Tool failure recovery | A failing or timing-out tool becomes a tool message the model can reason about; it does not abort the turn |
| Idempotent turns | A retried turn (same `turn_id`) returns the stored assistant message instead of appending a second one |
| Cost control | Each iteration charges the env and `agent:{name}` budgets before calling the provider; a long tool chain cannot overspend a cap |
| Auditability | Every run and tool call is journalled with the agent token identity (`act` chain), `arguments_hash`, status, approval, and duration |
| Retention | History beyond the env policy window is archived to Storage; the conversation skeleton is retained |
| Discovery | `GET /v1/tools` returns the tools the caller's permissions admit, so a UI can show what an agent may do |

### 3.5 Operations

| Capability | Business rule |
|---|---|
| Budgets admin | Env-wide (`'*'`) + per-feature caps with `reject`/`degrade`/`queue` enforcement |
| DLQ | Failed summary/classification/document jobs land in `ai.dlq` for manual replay; embedding jobs retry via consumer redelivery; malformed payloads are acked (poison-pill guard) |
| Evaluations | `POST /v1/evaluations/run` - synchronous inference per test case with assertion checks and score reporting |
| Costs | `POST /v1/costs` - cost rollups attributed per `{env_id, feature, model}`; cost normalized per 1M tokens when the provider does not return explicit cost |
| Traces | `GET /v1/traces` - trace lists (1-500); retention via Cron-bound archive + delete (`/v1/internal/traces/archive` proxy-back) |
| Trace archive | Archive then delete cycle keeps the hot table bounded |
| Filters admin | Env rules (tenant-configurable, Shield-gated) with input/output stages and blocked-terms lists |

## 4. Business Events (Outbound)

Event family `ai`; names follow `sentin8:ai:{resource}:{operation}`.
Traces insert in the same transaction as the response decision - a trace
row exists for every completed or failed inference.

| Event | When |
|---|---|
| `sentin8:ai:prompt:updated` | Prompt registry change (same transaction) |
| `sentin8:ai:document:ready` | Document pipeline completed (chunks embedded + stored) |
| `sentin8:ai:conversation:created` / `:archived` | Conversation lifecycle |
| `sentin8:ai:run:completed` | An agent turn closed, with its `stop_reason` |
| `sentin8:ai:turn:delta` | Streamed assistant delta for a live turn (SSE tier) |
| `sentin8:ai:tool:updated` | Tenant tool registry change |
| `sentin8:ai:agent:updated` | Agent or agent-policy change |
| `sentin8:ai:approval:decided` | A human approved or denied a paused action |
| `sentin8:ai:provider:updated` | Provider route change (also the route-cache invalidation key) |
| `sentin8:ai:{job_type}:job` | DLQ replay re-emits the job event |
| Stat envelopes | Token usage, latency, cache hits, cost - fire-and-forget (a Stat outage never blocks inference) |

**Inbound (consumed):** `*:document:uploaded` (any vertical) → document
pipeline; `sentin8:ai:agent:turn_requested` → open an agent turn;
cron-triggered `sentin8:ai:trace:archive` (trace retention),
`sentin8:ai:embedding:stale` (stale re-embed scan), and the
model-migration sweep (`POST /v1/internal/schedules/run`).

## 5. Business Rules & Invariants (the "always true" guarantees)

1. **Prompt versions are immutable** - an update creates a new version; duplicates 409.
2. **`target_env_id` is REQUIRED** on data endpoints - no silent fallback to the token env (cross-tenant read guard).
3. **Credential references only** - provider keys never stored in `ai.providers`; resolution order: Secrets ref → env backend; rotation requires no service restart.
4. **Filters run both directions** (input + output) with a persistent PII deny-list; output moderation cannot be skipped by model override.
5. **Budget checks precede provider spend** - a rejected request never reaches a provider.
6. **DLQ replay is manual** - failed jobs never auto-retry past consumer redelivery; malformed payloads are acked.
7. **Traces share the request's transaction** - a trace row exists for every inference, carrying cache provenance (`hit`/`miss` + prompt-hash).
8. **Shield (step 5) is the only gate** - no handler scope checks; the scope-mirror policy set denies fail-closed.
9. **The model never executes** - it emits tool calls; the gateway validates the
   arguments, checks the caller's permission, applies the side-effect class, and
   only then dispatches. No path skips the gateway.
10. **Every agent loop is bounded** - `max_turns`, token + cost budget, and a
   wall-clock deadline; a turn always ends with a stop reason from the closed set.
11. **Conversation history lives only in AI** - modules, workflows, and clients
   address a conversation by id and never hold authoritative transcript state.
12. **Tool authority is the caller's, never AI's** - the per-run agent token
   carries the owner and act chain, and Shield evaluates it.
13. **A tool result is re-moderated before it enters the transcript** - tool
   output is untrusted model input.
14. **A failing tool does not fail the turn** - the error is returned to the
   model; only provider terminal errors and guards terminate the run.
15. **Retrieval is permission-filtered** - results never cross the caller's data scope.
16. **No `unsafe` blocks in the service.**
17. **Direct consumers over Func** - embedding/summary/document reactions are first-class concerns consumed from the service's own stream families; job envelopes are payload-complete (no callback fetches).

## 6. Target-User Roles & Use Cases

| Persona | What they do with Sentin8:AI |
|---|---|
| Vertical developer | Calls completions/chat/embeddings/retrieval against prompt ids - never embeds vendor SDKs; composes domain behavior via prompts |
| Prompt author | Creates/versions/pins prompts; declares output schemas; runs evaluations |
| Agent author | Defines tools (schema + target + side-effect class), composes named agents from a prompt and a tool set, and sets the env agent policy |
| Application user | Holds conversations: sends turns, receives answers that used real tools, and approves irreversible actions when asked |
| Edge-function author | Uploads a Sentin8:Func module that calls a model through `ai_infer` - no integration work |
| Platform operator | Manages budgets, filters, DLQ replay, provider routes, tools, agents, and admin UI pages |
| Compliance/audit | Reads traces (cache provenance, safety verdicts, spend) and agent run/tool-call records with the act chain |
| Vertical service | Emits `document:uploaded` (or `agent:turn_requested`) and lets the AI plane react asynchronously |
| Business owner | Sees cost rollups per env/feature/model/agent; budget enforcement modes govern spend |

## 7. KPIs / Success Criteria

- **Cost governance**: budgets gate before provider spend, **per loop iteration**; cost attributed per `{env_id, feature, model}` and per agent; degradation visible in traces.
- **Safety**: input, output, and tool-result moderation with PII stripping; prompt-injection baseline rules are code (unaffected by tenant config).
- **Auditability**: every inference traced (tokens, latency, cost, safety verdicts, cache provenance); every agent run and tool call journalled with the act chain and `arguments_hash`.
- **Agent containment**: 100% of runs terminate with a recorded stop reason; zero tool executions without schema validation and permission check; zero irreversible actions without a recorded approval.
- **Customization**: a tenant can add a tool, agent, provider, or policy through the admin/APIs without a platform change or redeploy.
- **Reliability**: provider outages fail over via routing chains; a Stat/Flow/Cron/Storage outage never blocks inference (log-only degradations).
- **Tenant safety**: RLS + required `target_env_id` + permission-filtered retrieval + owner-scoped conversations - zero cross-tenant or cross-user leakage.

## 8. Dependencies & Reliance on Other Services

| The business relies on… | For |
|---|---|
| Sentin8:Auth | Bearer verification; JWKS; per-run agent token minting (`token_tp=agent`) |
| Shield (Sentin8:Policy) | Authorization decisions (live roles) on every route **and every tool dispatch** |
| Sentin8:Bus | Direct consumer groups for embedding/summary/document jobs; agent-turn triggers; outbox event publishing |
| Sentin8:Flow | Execution of `flow_workflow` tools (including their approval waits) |
| Sentin8:Func | Execution of `func_module` tools; and, in the other direction, modules calling `ai_infer` |
| Sentin8:Sys | `sys.service_actions` - the action registry tools resolve through (no stored URLs) |
| Sentin8:Cron | Trace archive, stale re-embedding, model-migration sweeps (self-registered schedules, proxy-back) |
| Sentin8:Storage | Document chunk text, trace archives, retained conversation history |
| Sentin8:Stat | Token/cost/latency/cache metrics (fire-and-forget) |
| Sentin8:Secrets | Provider credential resolution at call time |
| Valkey | Idempotency keys, exact-match response cache, tool rate-limit buckets |

## 9. Acceptance Criteria (what "done" looks like for the business)

1. A vertical can call chat/completions/embeddings/retrieval with a prompt id - no vendor SDK, no safety stack of its own.
2. Prompt updates create immutable new versions; duplicates rejected; platform history is never hard-deleted.
3. A transient provider outage fails over to the fallback model; retries are bounded; terminal errors fail fast.
4. Budget enforcement blocks (or labels) spend BEFORE the provider call - a rejected request never reaches a provider.
5. Every inference is traced (tokens, latency, cost, safety verdict, cache hit/miss) in the same transaction as the response.
6. A conversation keeps its history: turn N sees turns 1..N-1 **and** the results of every tool those turns called.
7. An agent turn that calls a tool receives the result and continues to a final answer in the same turn - the model is never asked again from scratch.
8. Every run terminates with a recorded stop reason; an agent loop cannot run unbounded.
9. A tool call with arguments that violate the tool's schema is denied and the model is told why; nothing is executed.
10. A tool the caller is not permitted to use is denied and audited; it is never silently dropped nor executed with widened authority.
11. An `irreversible` tool action pauses the run and executes only after a recorded human approval by someone who holds the required permission.
12. A retried turn (`turn_id`) returns the stored message rather than appending a duplicate.
13. A Sentin8:Func module can call a model through `ai_infer` and stays within the env budget; no per-service passthrough endpoint exists.
14. A tenant can register a provider, a tool, an agent, and a policy through the API/admin UI and see them take effect without a redeploy.
15. Every tool call is reconstructable after the fact from audit (run, tool, arguments hash, status, approval, duration).
16. Retrieval results are permission-filtered to the caller's data scope.
17. Document ingest works both synchronously (API) and asynchronously (Bus `document:uploaded` from any vertical) - the job envelope is payload-complete.
18. Failed jobs land in the DLQ for manual replay; malformed payloads never poison the consumer.
19. Provider credentials exist only as secret references - no key material in any application table.
20. Evaluations run prompt versions against test cases with assertion checks and score reporting.
21. Trace retention (archive then delete) runs as a Cron-bound loop; the hot table stays bounded.

## 10. Open Business Questions

1. **Agent cost ownership**: should an agent's spend be attributed to the env, the invoking user, or the agent itself for chargeback? The design attributes to `{env, feature=agent:{name}}` plus the env `'*'` budget; per-user chargeback would need a billing surface that does not exist yet.
2. **Approval routing**: approvals currently reach whoever holds `ai:agent:approve` in the env. If a vertical needs approval by a specific business role (a teller supervisor, a hotel manager), that mapping is a policy-set question, not an AI question - it should be authored as a Shield relation rather than an AI column.
3. **Conversation retention defaults**: policy-driven retention exists; the business default (how long a customer support conversation is kept) is a legal/compliance decision per vertical, not a platform default.
4. **Third-party tool marketplaces**: tools are tenant-authored today. A cross-tenant tool catalogue (an "app store for tools") is a business-model decision; the data model already has the shape (`ai.tools` with visibility) if it is wanted.
5. **Model cost transparency to end users**: showing a per-conversation cost to the application user requires a product decision about surfacing spend; the data is available (`conversations.cost_total`).
6. **Parallel tool execution**: deferred until a workload needs it; it must arrive with a deterministic transcript-ordering rule rather than ad-hoc concurrency.
7. **Cross-region provider routing**: deferred deliberately - residency is a deployment-topology concern (env to provider mapping), not a service concern.
8. **Token-accurate streaming cost accounting** rides the terminal-frame estimation the normalization already performs; provider-reported usage is used where available.

---

**Architecture & Design:** sentin8:ai and its underlying concepts were designed by [Hamid Jahanzad](https://www.linkedin.com/in/hamidjahanzad/).
