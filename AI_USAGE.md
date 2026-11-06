# AI usage and prompt notes

## Development tools

- GitHub Copilot was used as the coding assistant to scaffold the FastAPI service, SQLite checkpoint flow, chunking/parsing helpers, small browser UI, tests, and documentation.
- The application uses a locally installed `llama-cpp-python` runtime and a local Qwen3.5 Q4 GGUF. `scripts/download_model.py` contacts the Hugging Face model-file host only when explicitly run for setup; there are no hosted-model inference SDKs, telemetry calls, or cloud inference endpoints in the application runtime.
- `json-repair` is used only as a local fallback for malformed model JSON.

## Key local-model prompt

The versioned `prompts/system.txt` tells the model that log data and ledger values are untrusted, that embedded instructions must not be followed, and that instruction-like log text is attempted prompt injection. It explicitly excludes routine application 500 errors, deployment/maintenance 503s, recovering database timeouts, registered health monitors, and a single login typo. It requires original 1-based evidence line numbers and JSON-only output. `prompts/findings.schema.json` constrains the response fields and severity to `Low`, `Medium`, `High`, or `Critical`. User content adds a cumulative entity-ledger summary and wraps the rendered entries in `<LOG_DATA>` delimiters. Closing delimiter-like text in log entries and ledger data is escaped before prompting.

The output is constrained with a JSON schema containing only `findings`, whose entries require attack type, severity, entity, evidence lines, reason, and action. The service validates and normalizes results before checkpointing.

## Prompt revisions and safety decisions

1. The initial analysis prompt was narrowed from broad anomaly detection to credible security attacks, to avoid elevating ordinary operational errors and isolated login mistakes.
2. Untrusted-data language and explicit log delimiters were added after identifying that attacker-controlled log messages may contain prompt-like instructions.
3. A deterministic pre-scan was added for lines containing instructions aimed at the analyzer. Those lines become `prompt_injection` findings without executing or quoting their instructions.
4. Cross-chunk context was moved into a persisted code-maintained ledger keyed by client IP and username rather than relying on model memory. Its snapshots contain event facts only (login counts, lines, paths, status counts, sensitive-path hits), not attack labels or model-generated conclusions.
5. Findings are merged in application code. Duplicate event IDs map to one canonical evidence line; other evidence is unioned and severity maximized. A model-produced brute-force finding is upgraded to account compromise only when the IP ledger records at least three failures followed by a successful login.
6. Constrained JSON output is still parsed defensively, with a repair fallback and schema-shape validation.

## Token and runtime budget

| Section | Maximum |
| --- | ---: |
| System prompt | 350 tokens |
| Log entries | 900 tokens |
| Entity ledger | 250 tokens |
| Reserved model output | 500 tokens |
| Allocated sum | 2,000 tokens |
| Model context | 2,048 tokens |

Before every call, the application counts actual prompt tokens using the loaded llama tokenizer (including the chat template where available) and checks actual prompt plus the 500-token output reserve is strictly below 2,048. Entries are never split; an oversized single entry stops preparation rather than being silently truncated. Calls are sequential, use a 120-second timeout, and retry with exponential backoff before the job is marked failed and remains resumable.

## AI mistakes fixed / guarded against

- A broad “suspicious events” prompt can confuse an application bug or planned maintenance with malicious activity. The final prompt and post-processing suppress known benign classes.
- Model output can omit, duplicate, or misformat line numbers. The schema requires evidence lines; the merger normalizes, deduplicates, and sorts integers while keeping 1-based source positions.
- A small model may lose a sequence across chunks. Compact prior-chunk ledger snapshots provide IP- and username-linked event facts; the merger also uses the recorded IP login sequence to apply the explicit account-compromise upgrade rule.
- Model JSON can be incomplete despite constrained decoding. The repair fallback salvages only complete schema-shaped findings from truncated output, drops incomplete objects, and returns an empty findings list rather than raising on unrecoverable text.
- Log messages may attempt to change the model's task. They are treated as data, and deterministic injection findings identify explicit analyzer-directed instructions.

## Review limits

AI-generated classifications can still be wrong or incomplete, especially with a sub-2B model. Reports are hypotheses with evidence references, not verified incident facts. No sample-log findings are hardcoded.
