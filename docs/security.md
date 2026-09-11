# Security contract

## Outbound boundary

Explorer allows only the known read surface after exact node-tool schema checks. Guarded
execution uses a fresh descriptor, bounded JSON Schema subset, policy, encrypted decision,
lease, durable admission and redacted audit. The subset excludes references, regex patterns,
composition, oversized schemas, and recursive validation. Unsupported schemas are denied.
Remote content is untrusted; the WebUI uses escaped text and never `x-html`.

Current SAM describe responses omit remote risk annotations and provider labels. The adapter
reports this absence. An unknown-risk floor forces approval; it does not infer read-only safety.
The `sam-describe/v1` contract verifies only the fields SAM actually exposes. A richer future
schema must be evaluated explicitly before making stronger risk claims.

TCP connects to a numeric address from one checked resolution and verifies its peer address
before HTTP bytes leave. Configured origins, TLS hostname validation, no redirects, and no
proxy-environment inheritance prevent endpoint substitution. UDS uses Linux no-follow
parent descriptors and a pinned socket inode. These checks do not defend against a compromised
host/root or malicious code executing as the same trusted local user.

## Approval and recovery

Only authenticated, CSRF-protected server APIs issue approvals. Project, profile and chat
come from an existing Agent Zero context. Model arguments cannot select another local scope.
An operator confirms an exact five-minute decision, and its server-side lease has one use.
Arguments and lease identifiers are encrypted with a process-local key. Restart invalidates
pending decisions; durable replay/quota/stop state remains. Global project and default profile
use exact empty-string partitions, not wildcard matches. Chat identity must be nonempty.

Emergency disconnect sets the persistent profile barrier before best-effort lease cleanup.
Resume invalidates every old decision for that profile and does not reset its quotas.
Admission preceding disconnect may finish, and remote mutations cannot be undone locally.
An ambiguous SAM tool failure can have executed more than once because SAM may retry. The
plugin never retries a mutation. A lost result needs operator investigation before a new call.

## Credentials and protected content

Use a reference to one server-side secret source. Generic host config save/load hooks reject raw-token fields, invalid schemas and unknown keys before persistence or response; they do not read secrets during editing. Browser responses, generated configuration,
wrapper history, audits and exported reports exclude raw node credentials. The protected form
holds a payload only until preflight, then clears it. Changing chat clears displayed protected
state; stale responses and pre-stop refreshes are discarded.

Redaction does not erase text the host already accepted into model history. Never give a
node credential or protected payload to a model-controlled tool call. Ordinary native chat
remains an operator-selected data transmission channel; the plugin cannot infer the true
sensitivity of arbitrary prose. Use the guarded named form for destination-bound sensitive
requests, within the passport's allowed data class.

The generic Agent Zero model search and unrelated plugins/tools are outside the owned HTTP
adapter. In particular, a provider credential in the host's model settings can be sent by the
host model-search implementation. Prefer the project-secret reference and Observatory catalog.
Plugin settings do not establish host-wide network confinement.

## Inbound and deployment gates

The broker permits `service_info`, `ask_specialist`, and `finish_session` only. Session IDs
are bound to an immutable service contract and verified caller origin; they cannot select
local contexts, profiles, tools or files. Attachments are disabled. Limits cover bytes, time,
concurrency, request rate, sessions and idle retention. A declared profile must exist and
have the boundary plugin enabled. Local Tool Access and the Embassy execution hook are both
necessary; full real-agent execution and disable/drain lifecycle proof is still outstanding.

A bare `X-Peer-Id` from a loopback HTTP client is forgeable. The broker therefore requires a
trusted origin resolver and has no shipped public startup path. SAM's authenticated mesh
attribution alone does not authenticate the final local TCP hop. Publication remains closed.

Sovereign mode remains blocked pending a tested binary contract, TUN translator, token/bundle
lifecycle and real negative-network evidence. No claim of zero unapproved egress is made.
