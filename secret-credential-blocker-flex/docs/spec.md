# Secret & Credential Leakage Blocker — specification

This spec covers PDK 1.10.0 and has been tested on Flex Gateway 1.12.1 (minimum runtime 1.9.3).

## 1. Scope

One policy that detects secrets and credentials in REST, MCP, A2A and LLM (OpenAI,
Anthropic, Gemini) traffic and
**blocks**, **redacts** or **monitors** them. It covers the request leg always and
the response leg optionally. It is stateless: it makes no outbound calls and stores nothing.

Invariants:

- A raw secret value is never logged, stored or returned to the client. Logs carry
  the detector, the location and a fingerprint. Client errors carry the detector and
  location only (and nothing at all with `errorDetail: false`).
- In `redact`, if a body cannot be rewritten, the policy fails closed: the request is
  blocked, and for a response the body is replaced with the error.
- An invalid configuration (a bad regex, skip path or fingerprint, or an out-of-range
  number) stops the policy from loading. It never runs half-configured.

## 2. Request flow

1. **Headers stage**
   - Each header in `scan.headers` is scanned, except `Authorization`, `Cookie` and `Proxy-Authorization`.
   - If `scan.queryParams` is on, query parameters are percent-decoded and scanned. Locations are `header:<name>` and `query:<name>`.
   - With `redact`, header values are rewritten in place. The query is rewritten by setting `:path`, re-encoding only the pairs that had findings; every other byte of the URL is kept.
2. **Early block**
   - On a header or query finding with `block`, the request is rejected right away.
   - Exception: a POST with a body whose protocol is not yet known (and `protocol` is not `rest`). Its body is read first so that an MCP or A2A client gets an error in its own JSON-RPC envelope, with its `id` echoed.
3. **Unscannable check.** A body with a `content-encoding` other than `identity`, or a `content-length` above `maxBodyBytes`, follows `oversizeBehavior`:
   - `failOpen`: forwarded, with a warn log and a policy violation.
   - `failClosed`: rejected with `PAYLOAD_UNSCANNABLE`.
4. **Body stage.** The request is classified (§3) and the plan for that operation is scanned (§4).
5. **Outcome.** Every finding logs and raises a policy violation, whatever the action. Then:
   - `block` returns the error (§6).
   - `redact` forwards the rewritten body; if the rewrite fails, the request is blocked.
   - `monitor` forwards the request unchanged.

gRPC (`application/grpc*`) is never scanned.

## 3. Classification (`protocol: auto`)

| Signal | Protocol |
|---|---|
| `x-llm-input-format` or `x-input-format` header = `openai` / `anthropic` / `gemini` (case-insensitive) | LLM, in that format |
| `A2A-Version: 1.0` header or `?A2A-Version=1.0` (key case-insensitive) + HTTP+JSON route | A2A v1 HTTP+JSON |
| HTTP+JSON route whose last segment has `:` (e.g. `/acme/message:send`) | A2A v1 HTTP+JSON |
| JSON-RPC 2.0 body with an A2A v1 method (`SendMessage`, `GetTask`, …) | A2A v1 JSON-RPC |
| JSON-RPC 2.0 body with an A2A v0.3 method (`message/send`, `tasks/get`, …), or a v0.3 method + v1 header | A2A v0.3 / v1 JSON-RPC |
| JSON-RPC 2.0 body with an MCP method (or `notifications/*`) | MCP |
| Other JSON-RPC 2.0 body | generic JSON-RPC (`params` scanned) |
| Anything else | REST |

The HTTP+JSON routes are `message:send`, `message:stream`, `tasks`, `tasks/{id}`,
`tasks/{id}:cancel`, `tasks/{id}:subscribe`, `tasks/{id}/pushNotificationConfigs[/{id}]`
and `extendedAgentCard`, each with an optional tenant prefix. A JSON-RPC batch is
scanned as a whole document.

When `protocol` is forced, auto-detection is skipped. `rest` treats everything as REST.
`mcp` and `a2a` use the matching vocabulary and error shapes.

**LLM traffic.** A gateway policy has no runtime field that names the asset type it is
applied to. The signal used instead is the request-format header that the LLM proxy's
first policy sets on every request. With `protocol: auto`, that header is the only way
a request is treated as LLM traffic, so the same body on a REST API stays REST. With
`protocol: llm`, every request is LLM traffic. The header still names the format; when
it is absent, the format comes from the request:

- a `:generateContent` / `:streamGenerateContent` path, or a `contents` member → Gemini;
- a `/messages` path, or `messages` plus `system`, `anthropic_version` or `stop_sequences` → Anthropic;
- `messages`, `input` or `prompt` → OpenAI (Chat Completions, Responses, Completions);
- otherwise the body is scanned whole, with LLM error shapes.

A body whose shape does not match any format is scanned as a whole document.

## 4. What is scanned

| Protocol / operation | Scan roots |
|---|---|
| MCP `tools/call`, `prompts/get` | `$.params.arguments` |
| MCP `resources/read` | `$.params.uri` |
| MCP `completion/complete` | `$.params.argument` |
| MCP notifications, `*/list`, `initialize`, `ping`, … | not scanned |
| A2A JSON-RPC (v0.3, v1) | `$.params` |
| A2A v1 HTTP+JSON | whole body |
| REST JSON | whole body (`scan.restBody`) |
| REST `application/x-www-form-urlencoded` | each field, location `form:<name>` |
| REST `text/*`, XML, unparseable JSON | whole body as text, location `body` |
| `multipart/form-data`, `multipart/mixed` | see below (`scan.multipart`) |
| Other content types (images, octet-stream, …) | not scanned |
| LLM OpenAI | `$.messages[*]` (content, text parts, `tool_calls[*].function.arguments`), `$.input`, `$.instructions`, `$.prompt` |
| LLM Anthropic | `$.messages[*]` (text, `tool_use.input`, `tool_result.content`), `$.system` |
| LLM Gemini | `$.contents[*]` (`text`, `functionCall.args`, `functionResponse.response`), `$.systemInstruction` |

Within JSON, every string value is scanned, and so is every member name/value pair
(the key-name check, §5). Finding locations are JSON paths like
`$.params.message.parts[1].text`.

**Base64 parts.** With `scan.decodeBase64Parts` on, string members named `bytes`,
`raw` or `blob` are handled as follows:

- `bytes` covers A2A v0.3 `file.bytes`, `raw` covers A2A v1 parts and `blob` covers MCP resources.
- They are decoded, up to `scan.maxDecodedBytes`.
- If the result is UTF-8 text, it is scanned. The location gets a `(base64)` suffix, e.g. `$.params.message.parts[1].file.bytes(base64)`.
- On redact, the text is re-encoded.
- Binary content is skipped.

**LLM requests.**

- Model, sampling parameters and tool *definitions* (`tools`, `functions`) are not scanned.
- Tool-call arguments are JSON-encoded strings and are scanned as text, so a
  `"password": "..."` inside them is still found by `generic_secret_assignment`.
- Media (`data:…;base64,` URIs, Anthropic `source.data`, Gemini `inlineData.data`,
  OpenAI `input_audio.data` / `file_data`) is decoded under `scan.decodeBase64Parts`
  (up to `scan.maxDecodedBytes`). Text documents are scanned and re-encoded on redact;
  images, audio and other binary data are skipped, never scanned as base64 text.
- `llm.scanScope: latestTurn` scans only the items after the last model turn
  (`role: assistant` / `model`, or an OpenAI Responses `function_call`) and the
  instructions only on a first turn (no model turn yet). Clients resend the whole
  conversation on every call, so with `all` an earlier secret is reported again on each
  call (and, under `redact`, redacted again: the client keeps its own unredacted copy).
  **Earlier turns are forwarded unscanned with `latestTurn`**, so a secret left in the
  history (for example after a blocked call the client did not drop) reaches the model
  on the next call. Use `latestTurn` for `monitor` rollouts; keep `all` with `block` and
  `redact`.

**Multipart.**

- The boundary is taken from `Content-Type` (quoted or bare, at most 70 characters).
- Which parts are scanned:
  - `*/json` and `*+json` parts are walked as JSON, location `multipart:<name>.<json path>`.
  - Form-urlencoded parts are scanned field by field.
  - `text/*` parts, and untyped parts without a `filename`, are scanned as text, location `multipart:<name>`.
  - Any other part (files, binary) is skipped.
- Unnamed parts are reported as `multipart:[<index>]`.
- Redact rewrites only the affected part bodies. Every other byte is reassembled unchanged.
- A body that cannot be parsed follows `oversizeBehavior`.

**A2A push-notification config.** For `tasks/pushNotificationConfig/set` and
`CreateTaskPushNotificationConfig`, the members `authentication`, `token` and
`credentials` are skipped wherever they appear. They are the webhook credentials the
agent needs. The webhook `url` is still scanned.

**Skip paths** (`allowlist.skipPaths`):

- JSON paths support `.key`, `['key']`, `[n]`, `*`, `[*]` and `..` (any depth). Matching is by prefix: `$.a` skips everything under `$.a`.
- `header:<name>` is case-insensitive.
- `query:<name>`, `form:<name>` and `multipart:<name>` are case-sensitive.

## 5. Detection

The pipeline for each scanned string is: keyword prefilter, then regex, then
validator, then allowlist, then overlap resolution (the higher-priority detector wins
an overlapping span). Strings shorter than 8 bytes are not scanned.

| Detector | What it matches |
|---|---|
| `aws_access_key_id` | `AKIA`/`ASIA`/`ABIA`/`ACCA`/`A3T…` + 16 base32 chars |
| `aws_secret_access_key` | 40-char key **only** with context: a member/assignment named like `aws_secret_access_key` / `SecretAccessKey` |
| `gcp_api_key` | `AIza` + 35 chars |
| `gcp_service_account` | a JSON object with `"type": "service_account"` and a `private_key` |
| `azure_storage_connection_string` | `AccountKey=` / `SharedAccessKey=` + base64 key (only the key is redacted) |
| `azure_sas_token` | SAS `sig=` signature (only the signature is redacted) |
| `github_token` | `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_` + 36, `github_pat_` fine-grained |
| `gitlab_token` | `glpat-` and related prefixes |
| `slack_token` / `slack_webhook` | `xox[abposr]-…`, `xapp-…` / `hooks.slack.com/{services,workflows,triggers}/…` |
| `stripe_key` | `sk_live_`, `sk_test_`, `rk_live_`, `rk_test_` |
| `anthropic_api_key` / `openai_api_key` | `sk-ant-…` / `sk-…`, `sk-proj-…` |
| `jwt` | three base64url segments whose header decodes to JSON with `alg` |
| `private_key_pem` / `ssh_private_key` | `-----BEGIN … PRIVATE KEY-----` / OpenSSH key blocks |
| `db_connection_string` | `postgres://`, `mysql://`, `mongodb(+srv)://`, `redis://`, … with a password; ADO `Password=` strings |
| `basic_auth_url` | `scheme://user:password@host` |
| `generic_secret_assignment` | `password=`, `secret: …`, `api_key=` style text, and JSON/form/query members whose **name** marks a credential (`password`, `api_key`, `access_token`, `client_secret`, …) with a value that looks like a secret (≥ 8 chars, no whitespace, a digit/symbol or mixed case, and not a placeholder like `<token>`, `${X}`, `changeme`, `xxxx`) |
| `high_entropy_string` | opt-in (`entropy.enabled`): tokens ≥ `minLength` with Shannon entropy ≥ `threshold` bits/char. Hex strings and UUIDs are ignored |
| custom | `customPatterns[].name`: wrapped in `\b…\b` unless anchored; a `(?P<secret>…)` group limits redaction to that group |

Redaction replaces only the secret span with `[REDACTED:<detector>]`.

**Fingerprints.** The first 12 hex characters of
`SHA-256(fingerprintSalt + value)`, shown as `sha256:<12 hex>`. With no salt, you can reproduce it offline: `printf %s "$VALUE" | shasum -a 256 | cut -c1-12`.
With a salt set, fingerprints can't be compared across deployments.

**Allowlist.** A finding is dropped when any of these match:

- its fingerprint is in `allowlist.fingerprints`;
- its exact value is in `allowlist.values` (stored as hashes once the policy loads);
- its value fully matches a regex in `allowlist.patterns`.

## 6. Error shapes

Codes: `-32602` (invalid params) for request blocks, because the client can fix the
input; `-32603` for response blocks; `-32600` for unscannable requests. The A2A
`-32001…-32009` range is not reused.

| Protocol | Request block | Response block |
|---|---|---|
| REST | `400 application/problem+json` `{type: https://docs.p4a.ai/problems/secret-detected, title, status, detail, findings[{type, location}]}` | body → problem object, `status: 502` |
| MCP | `200`, JSON-RPC error `-32602`, `data {reason: SECRET_DETECTED, detectors[], paths[]}` | `tools/call`: `result {isError: true, content: [{type: text, text}]}`; other methods: `-32603` |
| A2A v0.3 | `200`, `-32602`, `data` is a string `"SECRET_DETECTED (github_token at $.params…)"` | `-32603`, string data |
| A2A v1 JSON-RPC | `200`, `-32602`, `data: [{"@type": "type.googleapis.com/google.rpc.ErrorInfo", reason, domain, metadata {detectors, paths}}]` | `-32603`, `SECRET_DETECTED_IN_RESPONSE` |
| A2A v1 HTTP+JSON | `400 {error {code: 400, status: INVALID_ARGUMENT, message, details: [ErrorInfo]}}` | body → `{error {code: 500, status: INTERNAL, …}}` |
| LLM OpenAI | `400 {error {message, type: invalid_request_error, code: secret_detected, param: null}}` | body → same with `type: server_error`, `code: secret_detected_in_response` |
| LLM Anthropic | `400 {type: error, error {type: invalid_request_error, message}}` | body → same with `api_error` |
| LLM Gemini | `400 {error {code: 400, status: INVALID_ARGUMENT, message, details: [ErrorInfo]}}` | body → `{error {code: 500, status: INTERNAL, …}}` |
| Unscannable + `failClosed` | `413` problem (`payload-unscannable`) / `-32600 PAYLOAD_UNSCANNABLE` / v1 `413 INVALID_ARGUMENT` | body → same error |

LLM errors put the detectors and locations in `message` (unless `errorDetail: false`),
so the vendor SDKs show them in their regular API error. A `400` is not retried by the
SDKs. JSON-RPC errors echo the request `id`. In a response block the `id` comes from the
upstream payload when present. `ErrorInfo.metadata` values are always strings, as
`google.rpc.ErrorInfo` requires. `errorDomain` defaults to `p4a.ai`.

## 7. Response leg (`responseScanning.enabled`)

- The leg runs only when the request was forwarded. The headers and body states are
  used separately; the combined state can hang the response leg.
- Content types:
  - Scanned: JSON, `text/*`, XML, an empty content type, and `text/event-stream`.
  - Not scanned: everything else.
- For JSON-RPC responses, `result` and `error` are scanned. For everything else, the whole document is scanned.
- **The HTTP status can't change** once the upstream has answered. A blocked response
  keeps its status, and its body is replaced with the error from §6.
- `responseScanning.action`: `inherit` (the request action), `block`, `redact` or `monitor`.
- Compressed or oversized responses follow `oversizeBehavior`. `content-encoding` is
  removed only when the body is actually replaced.

**SSE** (`text/event-stream`):

| `sseMode` | Behavior |
|---|---|
| `stream` (default) | Each chunk is split into events (LF or CRLF, blank-line terminated), and an incomplete trailing event is held until the next chunk. Each `data` value is scanned as JSON/text. Redact rewrites the event in place and keeps `event:`/`id:`/`retry:`. Block replaces the offending event with an error event and drops the rest of the stream. `[DONE]` sentinels pass. |
| `buffer` | Same rules applied to the whole stream at once (higher latency) |
| `monitor` | Read-only: findings are logged and the stream is untouched |

When `responseScanning.action` resolves to `monitor`, SSE is handled as `monitor`.

**LLM streams.** A model streams its output a few characters per event, so a secret is
usually split across many events. For LLM traffic the completion deltas (OpenAI
`choices[*].delta.content` and `tool_calls[*].function.arguments`, Responses
`*.delta`, Anthropic `delta.text` / `partial_json`, Gemini `candidates[*].content.parts[*].text`)
are concatenated into one running text and scanned as a whole (the last 8–16 KiB are
kept). Location: `completion`. Events that carry no delta are scanned as JSON.

- `block` and `redact` both end the stream at the event that completes the secret,
  with a provider-native error event: OpenAI Chat `data: {"error": {…}}`, OpenAI
  Responses `event: error` + `{type: error, code, message}`, Anthropic `event: error` +
  `{type: error, error {type: api_error, message}}`, Gemini `data: {"error": {…}}`.
  Redact cannot take back the earlier part of the secret that was already sent, so it
  acts as block on LLM streams.
- `monitor` only reports.
- Non-streamed LLM responses are scanned as a whole document; redact rewrites only the
  affected strings.
In `stream` mode, an unterminated event at end of stream is dropped. SSE clients
discard such events anyway.

## 8. Logging and violations

Each finding produces one `warn` line:

```
[secret-blocker] <request|response> <rest|mcp|jsonrpc|a2a-0.3|a2a-1.0-jsonrpc|a2a-1.0-http|llm-openai|llm-anthropic|llm-gemini> op=<method|-> action=<block|redact|monitor> detector=<kind> location=<path> fingerprint=sha256:<12 hex>
```

An unscannable payload logs `[secret-blocker] request not scanned: <why>; passed unscanned (failOpen)`
or `... blocked (failClosed)`. Both cases raise a policy violation. The configuration is
never logged, because it may contain allowlisted values and the salt.

## 9. Configuration reference

| Property | Type / default | Validation |
|---|---|---|
| `action` | `block` \| `redact` \| `monitor` = `block` | |
| `protocol` | `auto` \| `rest` \| `mcp` \| `a2a` \| `llm` = `auto` | |
| `llm` | `{scanScope: all}` | `all` \| `latestTurn` |
| `disabledDetectors[]` | built-in names = `[]` | |
| `customPatterns[]` | `{name, regex}` = `[]` | valid Rust regex; `name` letters/digits/`_`/`-` |
| `entropy` | `{enabled: false, threshold: 4.5, minLength: 24}` | `minLength` 8…1024 |
| `allowlist` | `{values, fingerprints, patterns, skipPaths}` | fingerprints `sha256:<12 hex>`; valid regexes and paths |
| `scan` | `{headers: [], queryParams: true, restBody: true, multipart: true, decodeBase64Parts: true, maxDecodedBytes: 262144}` | `maxDecodedBytes` 0…4194304 |
| `responseScanning` | `{enabled: false, action: inherit, sseMode: stream}` | |
| `maxBodyBytes` | `1048576` | 1024…16777216; keep it below the gateway buffer. LLM conversations with long histories or images usually need 4–8 MiB |
| `oversizeBehavior` | `failOpen` \| `failClosed` = `failOpen` | |
| `errorDetail` | `true` | |
| `errorDomain` | `p4a.ai` | |
| `fingerprintSalt` | `""` (sensitive) | |

## 10. Rollout and false positives

Start with `action: monitor`, read the fingerprints and locations in the logs, then
tune the configuration:

- **URL-authenticated APIs** (`?key=`, `?sig=`, `?access_token=`): add `query:key` etc.
  to `allowlist.skipPaths`. Query scanning is on by default, so these APIs trip it.
- **Fields that legitimately carry credentials** (e.g. a tool whose argument *is* an
  API key): skip `$.params.arguments.apiKey`.
- **Noisy detectors**: `jwt` and `generic_secret_assignment`. Disable them with
  `disabledDetectors`, or allowlist specific fingerprints.
- **Test keys** that you want to let through: list them in `allowlist.values` (they are
  hashed when the policy loads).

## 11. Known limits

- A response block can't change the HTTP status (§7).
- Compressed bodies aren't decompressed. They follow `oversizeBehavior`.
- Binary multipart parts and binary base64 payloads aren't inspected.
- Redacting can leave a body that exceeds the buffer. In that case the request is
  blocked (fail closed).
- A secret split across two JSON string values, or across two SSE events, isn't seen
  as one value. Exception: LLM completion deltas (§7).
- On LLM streams, the part of a secret sent before the event that completes it has
  already reached the client (§7).
- On LLM proxies, the policy must run after the proxy's first policy, which sets the
  format header. It does so automatically on LLM proxy instances; on other API types
  use `protocol: llm`.

## 12. Tests

- `make test-unit`: detector, path, walker, protocol, multipart, query, SSE and error
  unit tests, plus in-process pdk-unit tests covering both legs. No Docker needed.
- `make test`: everything above, plus Flex 1.12.1 integration tests
  (`tests/integration.rs`) for REST, query rewrite, multipart, MCP, A2A v0.3/v1/HTTP+JSON,
  MCP response `isError`, SSE stream redact/terminate, LLM OpenAI/Gemini block,
  Anthropic redact and an OpenAI stream with a secret split across deltas. Needs Docker and
  `tests/config/registration.yaml`.
