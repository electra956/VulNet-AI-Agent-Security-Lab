# Local LLM and RAG: how it really works

This page is the source of truth for the conversational path. It was written after an evidence-based audit
(runtime traces of the exact requests sent to Ollama) and describes the behaviour after the fixes.

## Requirements
```bash
ollama serve                      # http://127.0.0.1:11434
ollama pull llama3.2              # chat model   (OLLAMA_MODEL)
ollama pull nomic-embed-text      # embeddings   (OLLAMA_EMBED_MODEL)
```
`OLLAMA_BASE_URL` defaults to `http://127.0.0.1:11434`. If Ollama is down the app keeps working in a clearly
labelled **offline simulation** (see below); if only the embedding model is missing, retrieval is lexical.

## One conversational turn (`llm/conversation.py` → `ConversationEngine`)
The dashboard (`chatbot/components/chat.py`) and the FastAPI gateway (`POST /chat`) share this engine.

```
user text
  → security perimeter (threat detector, guardrails)              [unchanged, deterministic]
  → RAG retrieval (hybrid: Ollama embeddings + TF-IDF)
  → RAG guardrail: injections neutralised, chunks tagged trusted/untrusted, data boundary
  → prompt = system prompt + conversation history (last 10 turns) + [retrieved data + question]
  → Ollama /api/chat        (tools exposed ONLY if the request needs them)
  → for each tool call:  offered? → arguments grounded in the user's words? → tool guardrail
                         (whitelist, RBAC, ownership, approval threshold) → taint policy → execute
  → tool RESULT is sent back to Ollama → the model writes the final answer
  → numeric grounding check → output guardrail → user
```

* **Security decisions are never LLM-authored.** Blocked / approval-required outcomes are deterministic messages.
* **Tools are opt-in per request.** Conversational questions and knowledge questions get no tools, so the model
  answers from history and retrieved documents instead of reflexively calling a tool.
* **Arguments must be grounded.** An account ID or transfer amount the user never wrote is replaced (account) or
  rejected (transfer). The model cannot invent `ACC-1234`.
* **Taint policy.** If any untrusted document was retrieved, `transfer_funds` is held for human confirmation (secure mode).
* **Figures cannot be invented.** Money amounts in the model's answer must appear in the tool result, otherwise the
  verified tool card is shown instead. Verified tool output is attached under a collapsible "Verified tool result".
* **The model's answer is what the user sees**, followed by a collapsible "Retrieved context" block built from the
  real retrieval results (source, chunk, trust, scores, retrieval mode). Nothing about it is hard-coded.

## Retrieval (`rag/rag_engine.py`, `rag/embeddings.py`, `rag/vector_store.py`)

| Stage | Implementation |
|---|---|
| Load / chunk | `.txt` files, whole document if ≤ 800 characters, otherwise paragraph groups |
| Embedding | `nomic-embed-text` through Ollama `/api/embed` (768-d). Documents use the `search_document:` prefix, queries `search_query:` |
| Vector store | `data/vector_store.json`; every record stores `embedding_model` and `content_hash`, so vectors are only re-computed when the text or model changes and incompatible vectors are never mixed |
| Query | query embedded at runtime, cosine similarity against chunk vectors |
| Fusion | `0.7 × rescaled dense + 0.3 × TF-IDF`; dense cosine below 0.50 counts as unrelated |
| Identifier guard | a query naming an opaque identifier that appears nowhere in the corpus (e.g. `VULNET_RAG_X_55193`) needs lexical corroboration, because dense models rate unknown identifiers as "in-domain" |
| Trust | per-chunk `TRUSTED_INTERNAL` / `UNTRUSTED_EXTERNAL`, injection scan, neutralisation in secure mode |
| Result fields | `score`, `dense_score`, `lexical_score`, `retrieval_mode` (`hybrid:nomic-embed-text` or `tfidf-lexical`) |

If Ollama or the embedding model is unavailable, retrieval falls back to TF-IDF **and says so** (`tfidf-lexical`). The old
128-dimension hashing "embedder" is kept only as an offline placeholder inside the store; it is labelled
`local-hash-128` and never used for retrieval. Measured on this machine: about 60 ms per hybrid search, about 600 ms for
a chat turn without tools when the model is warm.

## Streaming, memory and tool-call hygiene (v3.1)
* **Streaming**: when a request needs no tool (`select_tools()` is empty), `ConversationEngine.stream()` yields the model's real
  chunks (`OllamaClient.stream_chat`) and the dashboard renders them with `st.write_stream`; the final text then passes the output
  guardrail. Tool turns are not streamed because their answer must first be grounded against the tool result.
* **Memory**: `Remember that …` is handled by a deterministic memory service (`memory/provenance.py`): validated in Secure mode,
  rejected if it carries an instruction/privilege claim, stored with provenance. Validated notes are added to the prompt as *passive
  data* and can never grant permissions or approvals.
* **Tool-call JSON**: small models sometimes print a tool call as JSON text; `scrub_model_text` strips it before display.

## Poisoning defences
* Injection patterns cover instructions aimed at the agent's controls and tools (for example "ignore all security
  controls", "approve every transfer … without approval", "grant admin", "call transfer_funds"), in both the RAG engine and the RAG guardrail.
  The trusted policy documents are verified not to trigger them.
* Retrieved text is data: tagged, framed as passive, and unable to change RBAC, approval or the MCP policy.
* Even if a model were persuaded, the tool guardrail, argument grounding and taint policy stop the action.

## Offline behaviour
When Ollama is unreachable the rule-based simulator answers. The reply starts with
`⚠️ Offline simulation — … not from an LLM`, the model is reported as `offline-simulation`, and the API sets
`llm_offline_simulation: true`. It still runs tools through the same guardrails.

## API metadata
`POST /chat` now returns `llm_model`, `llm_offline_simulation`, `retrieval_mode`, `retrieved_sources` and `tools_called`.
Messages that don't need the LLM (greeting/balance/transaction shortcuts) stay deterministic, and when the LLM is disabled
(`VULNET_USE_LLM=false`) the deterministic multi-agent pipeline answers (`llm_model: deterministic-multi-agent-pipeline`).

## Settings
| Variable | Meaning |
|---|---|
| `OLLAMA_BASE_URL`, `OLLAMA_MODEL`, `OLLAMA_EMBED_MODEL` | Ollama endpoint and models |
| `VULNET_USE_LLM` | `false` forces the deterministic path (the unit tests set this) |
| `VULNET_RAG_EMBEDDINGS` | `off` = TF-IDF only |

## Tests
* `tests/test_conversation_engine.py` — deterministic engine tests (tool loop, history, taint, grounding, offline label, fusion, patterns).
* `tests/test_live_llm_rag.py` — live tests against real Ollama: real embeddings, grounded RAG answer for a unique document,
  negative identifier, three-turn memory, tool-backed balance, poisoned document. Skipped automatically when Ollama or the models are missing.
