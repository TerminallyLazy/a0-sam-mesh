# Compatibility and evidence

Assessment date: 2026-09-11. Local verification uses the framework interpreter in an isolated
networkless container. No enrolled SAM mesh or existing Agent Zero user container was started.
This is the `1.0.0-alpha.1` community preview; full v1 certification remains gated.

## Revision matrix

| Component | Exact observation | Verification |
| --- | --- | --- |
| Agent Zero local framework | `6a6cecff8527b164668c7a6ab2f76b6b1ed7cfa1` | Real installed Tool/Response loading, provider merge/removal, Flask auth/CSRF and native LiteLLM/OpenAI calls against local fixtures |
| Agent Zero upstream main | `b1cbd1f960a1a5c4482b324dcff4742aa67b7a51` | Native installed-community and complete framework-suite release target |
| SAM earlier plan snapshot | `3224aae8dc962d6e8d4a83c4fa1f2d3e84c6db0f` | Historical design evidence only |
| SAM protocol source inspected | `787374aa823d289a2aa15ee1791973f438cb295d` | Official MCP, inference, sandbox, bundle and network source inspected; fixture contracts only |
| SAM latest main observed | `077a43e2e89e544bc6ecfbf6b4607706490592ad` | Comparison changes only `internal/sambox/gateway.go`, `mesh.go`, and `mesh_test.go`; no live certification |
| SAM published release | `v0.1.0-alpha.9`, published 2026-09-07 | Release metadata observed; binary and enrolled-mesh matrix not exercised |

The framework image ID used was
`sha256:db4617788520154de9173c59b581f4f0c6ef7a6c75c01d4c2fbc689793896b10`.
Python 3.12.4, HTTPX 0.28.1, HTTPcore 1.0.9, cryptography 50.0.1, jsonschema 4.26.0,
FastMCP 3.2.4, LiteLLM 1.88.1 and OpenAI 2.41.1 were inspected. The pinned transport uses
HTTPcore's backend interface; a dependency upgrade needs its connection-boundary tests.
`scripts/compatibility-report.py` regenerates a dependency report without contacting SAM.

## Observed drift and adaptations

1. **Remote risk metadata remains absent.** Current `remoteToolDescription` contains peer,
   canonical tool name, description, input schema and optional output schema, not annotations
   or provider labels. The prior blanket execution block is replaced with an explicit
   `sam-describe/v1` observation contract and an unknown-risk, single-use approval floor.
   `risk_metadata_verified` remains false. Schema, recipient and passport drift tests remain
   active; no read-only classification is inferred from absent metadata.
2. **TCP is now connected-peer verified.** Each new connection resolves approved addresses,
   dials one numeric address, verifies the actual peer and preserves TLS SNI. A generic or
   substituted unverified transport is still denied before credentials or discovery. Tests
   cover wrong peer, address changes, forbidden destinations, no redirection and real local
   HTTP calls. UDS retains its descriptor-pinned Linux boundary.
3. **Schema CPU exposure is bounded.** The execution subset excludes regex, references and
   compositions and limits tree depth, node counts, strings, enum values and schema size.
   Complex remote schemas remain unsupported instead of running unbounded validators.
4. **Inference authentication differs by path.** The `/v1` facade treats Authorization as local
   node authentication and removes it. A named `/sam/<peer>/inference/<service>` proxy forwards
   Authorization to the provider. Named approved requests therefore use X-Sam-Authentication
   only and require the exact fresh discovered proxy root. Current SAM appends
   `/chat/completions` to that root; the plugin does not invent another `/v1` segment.
5. **Published sandbox contracts evolved.** Current source contains bundle issuer/audience,
   egress and ingress flags that older plans described as absent. The bundle is nested under
   `agent` and `egress`. Source presence is not local runtime, TUN, ingress or credential
   lifecycle certification. Sovereign remains blocked for those unverified dependencies.
6. **Publication is administrator-managed.** SAM has no dynamic service registration endpoint.
   A plan cannot claim to advertise a service. The final local origin boundary and an observed
   administrator-applied registration are required before the publication controller can be
   integrated. No fabricated registration API is called.
7. **Verification tooling drift.** pytest 8.4.2 uses `__wrapped__` for the fixture-body test.
   All asynchronous tests use unittest's isolated async support, so no pytest-asyncio plugin
   is needed. Ruff rules are explicitly pinned to Python errors, imports and unused names;
   its formatter is run separately, avoiding version-dependent default rule expansion.
8. **Upstream host history now remembers response state.** The installed-tool test now uses
   real `Agent` methods with local construction/state instead of a `SimpleNamespace` agent,
   retaining its assertion that model-authored arguments already enter host history. No host
   or runtime plugin workaround is needed.

Primary evidence:
[SAM MCP source](https://github.com/google/sam/blob/787374aa823d289a2aa15ee1791973f438cb295d/internal/node/mcp_handlers.go),
[SAM inference facade](https://github.com/google/sam/blob/787374aa823d289a2aa15ee1791973f438cb295d/internal/node/openai_facade.go),
[SAM sandbox command](https://github.com/google/sam/blob/787374aa823d289a2aa15ee1791973f438cb295d/cmd/sam-box/main.go),
[SAM release](https://github.com/google/sam/releases/tag/v0.1.0-alpha.9).

## Native inference matrix

| Case | Local real-framework fixture | Live SAM release/current main |
| --- | --- | --- |
| Streaming and non-streaming chat | Passed | Not run |
| Function/tool-call response through native `unified_turn` | Passed | Not run |
| Aggregate model listing | Adapter contract tested | Not run |
| 401, 403, 404, 413, 429, 503 mapping | Passed | Not run |
| Extra retries at host, LiteLLM and SDK layers | Zero observed for six error cases | Not run |
| Exact named proxy, one-use approval, no Authorization forwarding | Guarded component tested | Not run |
| Offline emergency before next native transmission | Passed | Not run |
| Full Agent Zero response-tool loop with a real model | Not certified | Not run |

Generic host model-search HTTP is outside the plugin's pinned transport. Prefer project
secrets and the Observatory catalog; see the README. Automatic routing never promises an exact
recipient. UDS native provider use, full OpenAI compatibility and full model coverage are not
claimed.

## Release limits

The local suite cannot certify a running mesh, provider policy, model compatibility across SAM
tags, full host UI lifecycle, real Embassy contexts with malicious callers, or network confinement.
Raw MCP, automatic native registration, a2a, semantic intent search and peer messaging remain
unavailable. Embassy requires a verified final-hop origin boundary. Sovereign deliberately cannot
start. Cold audit verification has work proportional to retained history; warm local performance
numbers are not a large-history or production latency SLA.

## Native community installation follow-up

Upstream Agent Zero at `b1cbd1f960a1a5c4482b324dcff4742aa67b7a51` passes actual ZIP install, scoped settings,
activation, discovery, API and uninstall checks; see [native-community.md](native-community.md).
Native settings save/reopen and protected form cleanup were browser-verified. No
core adaptation was necessary. The root MIT license is included and verified
through native license discovery and the document API. The public alpha repository and
release are linked from the README; Plugin Index inclusion requires upstream review.
These checks do not certify external SAM network behavior.
