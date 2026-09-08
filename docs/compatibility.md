# Core Task 6 compatibility and limitations

## Release posture

**Task 6 is not release-complete.** The native surface is implemented, but installed guarded
invocation remains unavailable rather than bypassing unverifiable remote risk metadata.
Do not enable sensitive/risky transmissions by changing a capability flag.

## Source evidence

| Component | Revision inspected | Evidence / result |
| --- | --- | --- |
| Agent Zero local and upstream main | `6a6cecff8527b164668c7a6ab2f76b6b1ed7cfa1` | Real Tool/Response imports, file-based class loading, canonical Tool Access identities and UDS status wrapper exercised in the framework interpreter. |
| SAM Task 5 handoff | `4aedfcab50d5c4b19aa962cbabf0629fbf5af1be` | Fetched source-pinned `mcp.go` and `mcp_handlers.go`; describe emits JSON in MCP text content. |
| SAM current main observed during Task 6 | `935dcf21bff50a9278b08c5e2884e9d53ac4379e` | `mcp_handlers.go` inspected and compared; simulated send-message handler removed. Describe/call contracts relevant to this task remain unchanged. |

Current SAM `remoteToolDescription` includes peer, canonical tool name, description, input schema
and optional output schema, **not annotations or provider labels**. Treating absent annotations as
verified empty metadata would miss changes upstream. The installed adapter therefore advertises
`risk_metadata_verified=False`, and the gate denies invocation. A tested, source-supported path
that retrieves the current complete descriptor is required before lifting this restriction.
Remote descriptions are not invented from node-level `tools/list` descriptors.

`discover_remote_services(type=inference)` can return a second text item containing invocation
instructions. The adapter reads the first JSON item and discards that untrusted hint. Tool search
is catalog/exact-name search, not semantic intent search. Required labels retain SAM any-of wire
semantics. No A2A, enrollment, publication, inference invocation or raw gateway is a native tool.

## Transport boundary

- All native TCP operations fail closed before sending a node credential or discovery request.
  The older general TCP client still has its previously reported connected-peer/DNS-rebinding gap;
  this task does not claim to fix or certify it.
- UDS connects traverse parent directories with no-follow descriptors, validate ownership/modes,
  pin the socket inode and connect through `/proc/self/fd`. New pool connections repeat validation;
  keep-alive reuse is disabled. Config resolution continues to own socket-root allowlisting.
- Linux/procfs and the inspected HTTPX/HTTPcore backend contracts are required. Same-UID/root
  compromise is outside this boundary. No portable transport guarantee is claimed.

## Persistence and lifecycle

Decisions are encrypted with a process-local Fernet key; arguments and lease bearers are not
plaintext database fields. Five-minute expiry is also inside the authenticated ciphertext.
Restart or another process's key cannot recover decisions: create a new preflight/approval.
Replay and per-chat quota state persist. One active invocation per exact session is admitted;
crash-left active slots remain blocked rather than being automatically restored. Lifecycle recovery
and authenticated approval/emergency API wiring belong to subsequent work and are not certified.

Scoped store instances are reused with a four-entry project/profile LRU. Audit append still has
O(retained rows) work and cold verification costs; cache budgets are per store, not a process RSS
cap. No transactions span awaited network calls. No performance SLA or release gate passed here.

## Verification boundary and remaining work

- Framework-runtime unittest fallback is used. Pytest and Ruff are unavailable and were not installed.
- Fixture-backed HTTP-over-UDS exercises the real client and adapter; no live SAM binary/release
  matrix or enrolled mesh was run.
- Nine installed wrappers, strict arguments, framework `Response(break_loop=False)`, Tool Access
  identities, bounded output and wrapper log redaction are exercised. This is not full WebUI,
  Tool Access enforcement, or model-loop history certification.
- The host may already have stored a model-authored preflight payload before tool execution.
  Wrapper log suppression cannot erase those earlier messages. Full history/secret guarantees
  need host integration tests and a protected payload-reference flow; do not send secrets via tools.
- Remote JSON Schema validation rejects references but does not yet have a proven CPU budget
  against pathological schema regex/composition. Keep execution disabled pending that gate.
- Detailed denial/cancellation audit coverage, complete error taxonomy at all gate boundaries,
  immediate cross-process emergency/dispatch ordering, and clean-checkout release validation
  remain unproven. No stable/beta release recommendation is made.
