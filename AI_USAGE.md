# AI usage and prompt notes

## Development tools

- GitHub Copilot was used as the coding assistant to scaffold the FastAPI service, SQLite checkpoint flow, chunking/parsing helpers, small browser UI, tests, and documentation.
- The application uses a locally installed `llama-cpp-python` runtime and a user-supplied Qwen3.5 Q4 GGUF. There are no hosted-model SDKs, telemetry calls, or cloud inference endpoints in the runtime path.
- `json-repair` is used only as a local fallback for malformed model JSON.

## Key local-model prompt

The system prompt tells the model that log data is untrusted, that embedded instructions must not be followed, and that only delimited evidence should be analyzed. It explicitly excludes routine application 500 errors, maintenance-window 503s, recovering database timeouts, registered health monitors, and a single login typo. It requires original 1-based evidence line numbers and JSON-only output. User content adds a cumulative entity-ledger summary and wraps the rendered entries in `<LOG_DATA>` delimiters. Closing delimiter-like text in log entries is escaped before prompting.

The output is constrained with a JSON schema containing only `findings`, whose entries require attack type, severity, entity, evidence lines, reason, and action. The service validates and normalizes results before checkpointing.

## Prompt revisions and safety decisions

1. The initial analysis prompt was narrowed from broad anomaly detection to credible security attacks, to avoid elevating ordinary operational errors and isolated login mistakes.
2. Untrusted-data language and explicit log delimiters were added after identifying that attacker-controlled log messages may contain prompt-like instructions.
3. A deterministic pre-scan was added for lines containing instructions aimed at the analyzer. Those lines become `prompt_injection` findings without executing or quoting their instructions.
4. Cross-chunk context was moved into a code-maintained per-IP ledger rather than relying on model memory. The ledger contains counts and line ranges, not model-generated conclusions.
5. Findings are merged in application code. Evidence is unioned and severity maximized; repeated failures followed by successful authentication upgrade brute force to account compromise.
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
- A small model may lose a sequence across chunks. The SQLite entity ledger provides cross-chunk counters and the application—not the model—performs the compromise-upgrade rule.
- Model JSON can be incomplete despite constrained decoding. The repair fallback and required `findings` array check prevent malformed results from being treated as reports.
- Log messages may attempt to change the model's task. They are treated as data, and deterministic injection findings identify explicit analyzer-directed instructions.

## Review limits

AI-generated classifications can still be wrong or incomplete, especially with a sub-2B model. Reports are hypotheses with evidence references, not verified incident facts. No sample-log findings are hardcoded.
