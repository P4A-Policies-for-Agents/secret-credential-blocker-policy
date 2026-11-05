<p align="center">
  <img src="secret-credential-blocker-definition/icon.png" alt="Secret & Credential Leakage Blocker logo" width="120">
</p>

# Secret & Credential Leakage Blocker

A MuleSoft Omni Gateway custom policy that finds API keys, tokens, private keys,
connection strings and other credentials in **REST**, **MCP**, **A2A (v0.3 and
v1.0)** and **LLM** (OpenAI, Anthropic, Gemini formats) traffic, then **blocks**, **redacts** or **reports** them before they reach
an upstream service, model, tool or agent. Built with the
[Policy Development Kit (PDK)](https://docs.mulesoft.com/pdk/latest/policies-pdk-overview)
**1.10.0** as a split-model project.

## Why

Agents copy whatever is in their context into tool arguments, prompts and
messages to other agents, and that context often includes credentials. A key pasted
into a chat ends up in an MCP `tools/call`, a token read from a file ends up in an
A2A `message/send`, and a tool result containing a connection string flows back to
the model. This policy stops that at the gateway, with errors in the native format of
each protocol so clients and agents can handle them. On LLM traffic the errors use the
provider's own error format, so OpenAI, Anthropic and Gemini SDKs raise a normal
API error.

## What it scans

| Traffic | Scanned |
|---|---|
| REST | JSON, `application/x-www-form-urlencoded`, `text/*`/XML bodies, `multipart/form-data` and `multipart/mixed` text/JSON parts |
| MCP | `tools/call` and `prompts/get` → `params.arguments`, `resources/read` → `params.uri`, `completion/complete` → `params.argument`. Notifications and list methods pass through. |
| A2A v0.3 | JSON-RPC (`message/send`, `message/stream`, `tasks/*`) → `params`, including base64 `file.bytes` |
| A2A v1.0 | JSON-RPC (`SendMessage`, …) and HTTP+JSON (`POST /message:send`, optional tenant prefix) |
| LLM | Requests on LLM proxy instances (format from the `x-llm-input-format` header the proxy sets; `protocol: llm` also detects it from the body). Message text, system prompts, tool-call arguments and tool results, plus base64 text documents. Model, parameters, tool definitions and images are not scanned. `llm.scanScope: latestTurn` skips resent history. |
| All | Query parameters (on by default) and any headers you list in `scan.headers` |
| Responses | Optional (`responseScanning.enabled`): JSON/text bodies and SSE streams. LLM streams are scanned across deltas, so a secret split over tokens is still caught. |

`Authorization`, `Cookie` and `Proxy-Authorization` are never scanned, because they
are expected to carry credentials.

## Detectors

AWS access key ID and secret access key (the secret only when its key name gives
context), GCP API key and service-account JSON, Azure storage connection string and
SAS token, GitHub and GitLab tokens, Slack tokens and webhooks, Stripe secret and
restricted keys, Anthropic and OpenAI keys, JWT (the header must decode to JSON with
`alg`), PEM and OpenSSH private keys, database connection strings with passwords,
URLs with embedded basic auth, and generic `password=`/`secret=` assignments or
members whose name marks a credential (`"api_key": "…"`). Every detector is on by
default. You can add your own named regexes (`customPatterns`) and turn on
high-entropy detection (`entropy.enabled`).

## What gets logged

One warn line per finding, with the detector, the location and a truncated SHA-256
fingerprint. **The raw value is never logged or returned.**

```
[secret-blocker] request mcp op=tools/call action=block detector=github_token location=$.params.arguments.q fingerprint=sha256:03aafb028d53
```

Copy a fingerprint into `allowlist.fingerprints` to silence a known false positive.
Every finding also raises a policy violation.

## Rolling out

1. Deploy with `action: monitor` and watch the logs.
2. Remove false positives:
   - `allowlist.skipPaths`: `query:key` for APIs that authenticate with `?key=`, `header:x-api-key`, `$.params.arguments.apiKey`, `$..password`, `multipart:avatar`, `form:pw`
   - `disabledDetectors` (`jwt` and `generic_secret_assignment` are the usual suspects)
   - `allowlist.fingerprints` or `allowlist.values`
3. Switch to `block`, or to `redact` where forwarding a scrubbed request is better
   than failing it.

## Configuration (highlights)

| Property | Default | Notes |
|---|---|---|
| `action` | `block` | `block`, `redact` or `monitor` |
| `protocol` | `auto` | `rest`, `mcp`, `a2a` or `llm` skip detection |
| `llm.scanScope` | `all` | `latestTurn` scans only the newest turn (earlier turns pass unscanned) |
| `scan.queryParams` | `true` | |
| `scan.multipart` | `true` | |
| `responseScanning.enabled` | `false` | `action: inherit`; `sseMode: stream`. On LLM streams a finding ends the stream with an error event (`redact` acts as `block`) |
| `maxBodyBytes` | `1048576` | LLM conversations usually need 4-8 MiB |
| `oversizeBehavior` | `failOpen` | Applies to too-large, compressed and malformed-multipart bodies |
| `errorDetail` | `true` | `false` removes detector names and locations from errors |

The complete reference, covering every property, the error shapes and the edge
cases, is in [`secret-credential-blocker-flex/docs/spec.md`](secret-credential-blocker-flex/docs/spec.md).

## Project layout

```
secret-credential-blocker-policy/
├── secret-credential-blocker-definition/   # GCL schema + Exchange metadata
└── secret-credential-blocker-flex/         # Rust implementation (wasm32-wasip1)
    ├── docs/spec.md
    ├── playground/                         # local Flex + httpbin
    ├── src/
    │   ├── lib.rs           # entrypoint + filter wiring
    │   ├── settings.rs      # validated runtime config
    │   ├── request.rs       # request leg (headers, query, body)
    │   ├── response.rs      # response leg (JSON/text, SSE)
    │   ├── detect/          # detectors, key-name and entropy checks, allowlist
    │   ├── protocol/        # REST/MCP/A2A/LLM classification, query, form, multipart
    │   ├── walk.rs          # JSON walk with paths and base64 parts
    │   ├── errors.rs        # protocol-native error bodies
    │   ├── sse.rs           # incremental SSE rewriter
    │   └── tests.rs         # pdk-unit tests
    └── tests/integration.rs # Flex Gateway (Docker) tests
```

## Build and test

```bash
cd secret-credential-blocker-definition && make build && make release-local
cd ../secret-credential-blocker-flex
make setup            # cargo-anypoint 1.10.0
make build-asset-files
make build            # wasm + policy YAML
make test-unit        # in-process tests, no Docker
make test             # + Flex 1.12.1 integration tests (needs Docker and tests/config/registration.yaml)
make run              # playground on http://localhost:8185 (needs playground/config/registration.yaml)
```

`registration.yaml` files contain credentials and are git-ignored.

## Publishing

Publish and release this policy only through the P4A platform (https://www.p4a.ai).

## License

Apache-2.0. See [LICENSE](LICENSE).
