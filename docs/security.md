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
necessary; the dedicated native execution hook rejects tools outside the immutable service
policy. Version 1 permits only the response tool. Existing project instructions and the
chosen model are part of the operator's disclosure decision.

A bare `X-Peer-Id` from loopback is forgeable. Run the signing gateway in an exclusive operator
node namespace. SAM verifies and replaces peer identity on its named HTTP route; the gateway
signs that identity, service, exact request, time, nonce and broker-incarnation challenge.
The broker accepts only the pinned Unix socket and verified signature. Agent Zero receives
only the public key. The private signer, trust and socket mount sources must be separate
and non-overlapping. Native SAM MCP forwarding lacks attributed callers and cannot execute
an Embassy tool. Read [Embassy operations](embassy-operations.md) for the required topology.

Sovereign requires a matching runtime receipt plus observed guest confinement before config
resolution can read any credential. The agent has no ordinary interface, node credential,
node administration socket or container-control socket. Its public TCP-only CONNECT adapter
permits explicit names and the bounded mesh facade; literal addresses, UDP, external DNS,
metadata and administration routes are denied. Credential expiry or node/socket replacement
drains the boundary. The UI gateway has separate default-deny IPv4/IPv6 rules and returns only
established UI traffic. Receipt freshness, source/binary hashes, read-only mounts and guest
privileges are checked. A kernel or binary mismatch leaves Sovereign unavailable.

This boundary assumes a trusted Linux host and operator. It cannot protect an agent from a
host administrator or certify a modified topology. Use [Sovereign operations](sovereign-operations.md)
to certify the actual host; a release's CI receipt is evidence, not a transferable deployment permit.
