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

A call is read from the code, not from what is written about it: a remark (also one at the end of a line of code, and
every line of a block remark or a Python docstring) and a text that runs over several lines make no call. One
exception is meant: a vector store named in the text of a query (`"select … <=> …"` over several lines) is still a
vector store. Not told apart yet: a JavaScript template that runs over several lines is read as code.

## Findings

| Rule | What it means | Rank |
|---|---|---|
| `LA-WALLET-DRAIN` | A route reaches a paid call and has **no login check and no rate limit that covers it**. One script in a loop runs up the bill. | high |
| `LA-WALLET-DRAIN` | …has one of the two but not the other (logged-in users with no limit, or a limit but no login) | medium |
| `LA-MODEL-OUTPUT-TO-TOOL` | Text a model wrote is run as a shell command, sent to the database as query text, run with `eval`, fetched as an address or opened as a file path: in the same function, or after a helper hands it back, in another file, or out of a tool call the model asked for. Prompt injection becomes code execution. | critical when a route reaches it; medium where a step of the way is a guess |
| `LA-PROMPT-FROM-INPUT` | Visitor text goes into a model call in a function that also calls tool-like APIs. Normal for a chat app; informational. | low |
| `LA-NOTEBOOK-SECRET` | An API key or token in a `.ipynb` code cell or a saved output (OpenAI, Anthropic, Google, Hugging Face, GitHub, AWS, Stripe, Slack, Replicate, or `api_key = "…"`). Placeholders are skipped. | critical (a secret) |

The wallet-drain and model-output rules are heuristic (`tool_confidence: LOW`, shown as "heuristic"): the login
check reads names the way `LW-AUTH-MISSING` does, the rate-limit check looks for a limiter that is put to work (on
the route, or on the app: `lantern/ratelimit.py`; a library that is only installed or only loaded counts for nothing
since 2026-11-11, and the finding then says so), and
the output-to-tool rule knows a model call by the library's own name for it. Since stage 5 of the roadmap of
2026-11-14 the data-flow step follows the model's text across functions and files (`lantern/flow.py`, with the origin
`model`): the trail is on the finding, step by step, and the finding is this rule's alone, never a finding about what
a request sent. The older reading, inside one function by the names of the lines, still runs beside it; one line is
one finding, and a line where the model's text arrives checked against a list of the code's own, or made a number, on
every way there is no finding. Lantern does not know what the prompt holds, so whether someone outside can steer the
text is said only where the request's text is on the same line, and is otherwise "not known". The notebook rule is exact.

## What it does not do yet

* Follow the answer of a model call made through a library the data-flow step does not name (`flow_rules.MODEL_CALL`;
  a new library is a new line there) or through the project's own HTTP code: only the older reading, inside one
  function, may still see it.
* Read prompt templates for secrets, or tool definitions for over-broad permissions (an agent with a shell tool).
* Cost estimates (tokens × price) per route; `max_tokens` is mentioned in the fix text, not checked.
* Training and evaluation pipelines: they map as Python, nothing AI-specific is said about them.
