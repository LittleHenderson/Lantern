# AI apps: what Lantern checks

Apps that call models are ordinary full-stack apps with three extra ways to get hurt: someone else spends your
money, the model's words get treated as commands, and keys leak through notebooks. `lantern/aiapp.py` covers
them. Everything is deterministic pattern work; a model is never asked to judge.

## On the map

Every function that calls a model, embedding, image or speech API, a vector store, or another pay-per-use service
(Stripe, email, SMS) gets a chip: **model call**, **vector store**, **payment API**, **sends email**. Hover for the
provider and line. The header counts model calls and notebooks. So a path reads "click → route → model call →
database" without opening the code. Providers recognised: OpenAI (and the Vercel AI SDK), Anthropic, Google,
Mistral, Cohere, Groq, Replicate, Hugging Face, Ollama, LangChain, LlamaIndex, Bedrock, Azure OpenAI; Pinecone,
Chroma, Weaviate, Qdrant, pgvector/Supabase, FAISS, Milvus; Stripe; Resend/SendGrid/Mailgun/Postmark/SES/
nodemailer/smtplib; Twilio/Vonage. Add more in `CALL_PATTERNS`.

## Findings

| Rule | What it means | Rank |
|---|---|---|
| `LA-WALLET-DRAIN` | A route reaches a paid call and has **no login check and no rate limit that covers it**. One script in a loop runs up the bill. | high |
| `LA-WALLET-DRAIN` | …has one of the two but not the other (logged-in users with no limit, or a limit but no login) | medium |
| `LA-MODEL-OUTPUT-TO-TOOL` | Inside one function, text read from a model response is later run as a shell command, a database query, `eval`, a web request or a file path. Prompt injection becomes code execution. | critical when a route reaches it |
| `LA-PROMPT-FROM-INPUT` | Visitor text goes into a model call in a function that also calls tool-like APIs. Normal for a chat app; informational. | low |
| `LA-NOTEBOOK-SECRET` | An API key or token in a `.ipynb` code cell or a saved output (OpenAI, Anthropic, Google, Hugging Face, GitHub, AWS, Stripe, Slack, Replicate, or `api_key = "…"`). Placeholders are skipped. | critical (a secret) |

The wallet-drain and model-output rules are heuristic (`tool_confidence: LOW`, shown as "heuristic"): the login
check reads names the way `LW-AUTH-MISSING` does, the rate-limit check looks for a limiter that is put to work (on
the route, or on the app: `lantern/ratelimit.py`; a library that is only installed or only loaded counts for nothing
since 2026-11-11, and the finding then says so), and
the output-to-tool rule follows assignments inside one function only. The notebook rule is exact.

## What it does not do yet

* Follow model output across functions (a helper that returns `response.choices[0].message.content` is missed).
* Read prompt templates for secrets, or tool definitions for over-broad permissions (an agent with a shell tool).
* Cost estimates (tokens × price) per route; `max_tokens` is mentioned in the fix text, not checked.
* Training and evaluation pipelines: they map as Python, nothing AI-specific is said about them.
