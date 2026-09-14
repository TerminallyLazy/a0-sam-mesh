# Compatibility and evidence

Assessment date: 2026-09-13. SAM Mesh installs as a native Agent Zero community plugin
without framework patches. Live acceptance uses disposable, separately enrolled SAM peers;
existing user containers and identities are not part of the certification environment.

## Revision matrix

| Component | Pinned version | Evidence |
| --- | --- | --- |
| Agent Zero | `b1cbd1f960a1a5c4482b324dcff4742aa67b7a51` | Native ZIP install/uninstall, scoped hooks/APIs, native model and Embassy message loops |
| Agent Zero current main | Same revision when refreshed September 13 | Separate hosted native integration matrix job |
| SAM published binaries | `v0.1.0-alpha.9` | Enrolled mesh discovery, real model response, Embassy caller isolation and withdrawal; Sovereign runtime matrix |
| SAM current main | `1966b79e7c6864876fc34722e78a050f1c23938c` | Independently built node/control plane, enrolled native real-model response and governed Embassy request |
| Framework image | `agent0ai/agent-zero@sha256:db4617788520154de9173c59b581f4f0c6ef7a6c75c01d4c2fbc689793896b10` | Linux ARM64 framework Python 3.12.4 |

The framework contains HTTPX 0.28.1, HTTPcore 1.0.9, cryptography 50.0.1, jsonschema 4.26.0,
FastMCP 3.2.4, LiteLLM 1.88.1 and OpenAI 2.41.1. The TCP transport uses HTTPcore's backend
interface; upgrades need the connection-boundary tests. `scripts/compatibility-report.py`
reports installed dependencies without contacting SAM. The plugin's stable version does
not change the upstream SAM release's alpha designation.

## Protocol adaptations

- **Missing risk annotations:** SAM's remote descriptors omit risk annotations and provider
  labels. `risk_metadata_verified` stays false. Every unknown-risk call needs one-use
  approval, with fresh schema, recipient, passport and payload binding. Bounded schema
  validation excludes references, regex, composition and excessive size/depth.
- **Inference authentication:** the `/v1` facade consumes local Authorization. Named
  `/sam/<peer>/inference/<service>` proxies forward Authorization to providers, so approved
  named requests use only `X-Sam-Authentication` for node authentication. No extra `/v1`
  segment is invented. Automatic routes can fail over and use any-of label matching.
- **Authenticated Embassy:** SAM's MCP forwarding loses caller identity. The separate named
  HTTP route verifies the mesh caller and replaces `X-Peer-Id`; an isolated operator gateway
  signs the exact request for the Unix-socket broker. The `SAM Embassy HTTP v1: ` descriptor
  selects this transport, without changing the unknown-risk approval floor. Anonymous MCP
  probes cannot execute tools. Static node service registration remains operator-managed.
- **Bounded specialist schema:** the optional `session_id` is an empty string for a new
  session. Its published schema stays within the strict execution subset; composition is
  not enabled merely to accommodate FastMCP's default schema generation.
- **Published sandbox:** `nano-init` bundles tun2connect. Its exact Go CONNECT header is
  accepted and stripped by the TCP-only boundary; arbitrary headers remain denied. Its
  synthetic dual-stack DNS is accepted only for the exact credentialless mesh facade in a
  verified Sovereign guest. General reserved-address restrictions remain unchanged.
- **Native startup:** the read-only source is prepared with required empty knowledge
  directories and the framework runs with `--dockerized=true`. Core source is unchanged.

Primary sources: [SAM release](https://github.com/google/sam/releases/tag/v0.1.0-alpha.9),
[SAM source revision](https://github.com/google/sam/tree/1966b79e7c6864876fc34722e78a050f1c23938c),
[Agent Zero source revision](https://github.com/agent0ai/agent-zero/tree/b1cbd1f960a1a5c4482b324dcff4742aa67b7a51).

## Native inference and Embassy acceptance

| Case | Evidence |
| --- | --- |
| Streaming, non-streaming and structured function output | Native framework fixtures exercise transport and host `unified_turn` integration |
| 401, 403, 404, 413, 429, 503 and retry suppression | Native local fixtures; zero extra plugin/host/SDK retries observed |
| Enrolled mesh model catalog and actual model response | Released and current-main SAM, native `sam_mesh` provider, real `gpt-6-astra`, response-tool `break_loop=true` |
| Governed specialist invocation | Current-main SAM, actual discovered schema, native preflight/approval/dispatch, real native context and model, one-use replay rejection |
| Caller/session isolation | Three enrolled identities, cross-peer and cross-service rejection, spoof overwrite, unsigned forwarding denial |
| Withdrawal and upgrade | Static declarations removed, node restarted with identity preserved, local MCP catalog empty and old route refused; identities preserved across binary upgrade |

The real OAuth-backed model used for acceptance supports Agent Zero's JSON response-tool
path. It rejects structured OpenAI function-tool requests. Structured function compatibility
is therefore fixture-tested, not certified for that live provider. Model families and
provider policies are not interchangeable. Generic host model search remains outside this
plugin's pinned client; prefer the Observatory catalog and project-secret reference.

## Supported limits

Embassy v1 permits only the response tool. It uses existing project instructions and a
selected profile; it has no shell, arbitrary file/URL, attachment or subordinate-agent
surface. Publication requires the exclusive signing-gateway namespace and an operator-applied
static node declaration. A healthy broker alone is not a public advertisement.

Sovereign requires the complete Linux runtime certification and a fresh receipt matching the
host boot, kernel, images, binaries, pack and read-only Agent Zero source. The tested Docker
Desktop `7.0.12-linuxkit` kernel is unsupported: published nano-init rejects its extra fallback
interfaces. No fallback to ordinary networking is provided. Pinned peer Embassy outbound
routes are unavailable through Sovereign's restricted facade; inbound Embassy uses its
separate signed gateway/socket deployment.

Raw MCP, automatic host MCP registration, A2A, semantic intent search and peer messaging
remain outside the supported surface. Cold audit verification scales with retained history;
warm local performance checks are not production latency guarantees. See
[release readiness](release-readiness.md) for the exact release evidence.

## Native setup and Observatory correction (1.0.1)

Published SAM alpha.9 returns `text/plain` body `OK` from `/healthz` and `/readyz`.
The adapter accepts that exact response only for these GET routes; arbitrary text,
non-success HTTP responses, MCP and model payloads retain strict validation.
Connection status verifies protected `/v1/models` access as well, because health is public.
Managed setup pins both release archives and the extracted sam-one/sam-node digests for
Linux arm64/x86_64. Startup is supervised through native hooks and preserves node identity.
The framework pin remains b1cbd1f960a1a5c4482b324dcff4742aa67b7a51; SAM main observed
2026-09-14 is af295d74219515e60b019f70561a2661b525b00f. Managed binaries remain pinned
to the tested published alpha.9 release.

Fresh MCP clients now send `initialize` and `notifications/initialized` before their first
session request. Concurrent first requests share one initialization. Explicit repeated
initialization is still rejected. Plaintext health acceptance never applies to model or
MCP payloads; authenticated model catalog access is required for ready status.
