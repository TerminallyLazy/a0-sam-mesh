# A0 SAM Mesh Embassy DOX

## Purpose

- Own the standalone `sam_mesh` community-plugin repository and its optional sovereign deployment pack.
- Keep runtime plugin files at repository root so the repository installs directly into `usr/plugins/sam_mesh`.

## Ownership

- Root `LICENSE` owns the MIT grant and contributor attribution; include it in every community package and verify it through native plugin metadata and document retrieval.
- `webui/logo.png` owns the generated brand asset; `webui/thumbnail.webp` is its square, under-20-KB Plugin Index derivative. `docs/branding.md` records provenance and the prompts.
- `.github/workflows/test.yml` owns static checks and the complete suite/native ZIP verification against pinned and current upstream Agent Zero in a disposable, network-disconnected framework runtime.

- `helpers/` owns validated domain, configuration, SAM transport, policy, leases, audit, inference, Embassy, and deployment support logic. `storage.py` anchors SQLite to verified inodes and coordinates WAL bootstrap; stale unlinked sidecar observations must be refreshed and any replacement fully revalidated.
- `tools/` and `prompts/` own the narrow Agent Zero model-tool surface and exact tool schemas.
- `helpers/gate.py` owns preflight and one-shot dispatch; `decisions.py` owns encrypted five-minute decisions, quota/replay state and offline stop controls. Process restart invalidates encrypted decisions.
- `helpers/tool_runtime.py` owns bounded project/profile store reuse and per-call client cleanup; `native_tools.py` owns exact runtime schemas, and `tool_output.py` owns bounded history output.
- `helpers/remote_tools.py` owns source-pinned SAM text-content contracts. Current SAM omits remote annotations: keep its metadata flag false and enforce the unknown-risk single-use approval floor.
- `helpers/uds_transport.py` owns Linux descriptor-pinned socket validation; `helpers/tcp_transport.py` owns numeric-address dialing and connected-peer verification. Unverified replacement transports must fail before any credential or discovery request.
- `hooks.py` owns native install/startup/settings setup and stop/pre-update/uninstall. Stop invalidates sealed pending decisions without clearing quota or emergency-stop state. Config validation never returns raw credentials. `helpers/managed_node.py` owns pinned binary installation, a single process supervisor, loopback-only mesh/node startup and private persistent identity. Never add `execute.py`.
- Missing `connection` in saved 1.0.0 configs means external; fresh defaults select managed. Sovereign always uses its certified external boundary. Managed setup never joins an external mesh or publishes a service automatically.
- `api/` owns authenticated, CSRF-protected plugin API handlers. Scope comes from an existing Agent Zero context; resume never restores prior decisions.
- `helpers/inference.py` owns native HTTP-client lifetime and durable call admission; `inference_gate.py` owns protected named-route payloads and one-shot approvals.
- `helpers/embassy_sessions.py` owns origin-bound native ephemeral sessions; `embassy_runtime.py` owns broker lifetime and scope revocation; `embassy_origin.py` and `embassy_gateway.py` own the signed final-hop boundary. Embassy v1 permits only the response tool. Operator-applied static registration is separate from broker health.
- `webui/` and `extensions/` own native Agent Zero UI surfaces and lifecycle integration. `main.html` is the plugin-list entry; settings inherit the host prototype’s `config` and `context`. Protected Observatory state is cleared on component destruction.
- `deploy/` owns the optional Sovereign deployment pack, TCP-only boundary, isolated UI gateway, runtime certification and rollback. `helpers/sovereign.py` validates operator receipts and observed guest confinement.
- `tests/` owns unit, contract, integration, adversarial, and release-gate evidence.
- `docs/` owns approved contracts, compatibility evidence, security guidance, and runbooks. `docs/release-readiness.md` records release gates; `docs/verification.md` records reproducible checks.
- `scripts/` owns dependency/source reporting, secret scans and disposable native ZIP verification. `verify-community.py` requires an explicit disposable-runtime marker and refuses an existing installation.

## Local Contracts

- The approved design in `docs/superpowers/specs/2026-08-31-a0-sam-mesh-embassy-design.md` is authoritative; execute the four plans in dependency order.
- Use test-first development and inspect meaningful failures before implementation.
- Default to Explorer and fail closed. Managed setup may enroll only its private local node into its own loopback mesh. Never silently enroll into an external mesh, publish, transmit sensitive data, or broaden model authority.
- Never accept or expose raw SAM tokens in ordinary plugin config, tool arguments, prompts, logs, chat history, browser responses, audit exports, or examples.
- Risky actions require server-owned, destination-aware, single-use approval leases. A model-controlled confirmation is not authorization.
- Preserve canonical discovered identifiers verbatim. Treat all remote content as untrusted.
- Plugin Python must use Agent Zero community-plugin import conventions when installed under `usr/plugins/sam_mesh` and must not modify Agent Zero core modules.
- Use Agent Zero Flask/`ApiHandler`, Alpine store gating, notification, extension, model-provider, and Tool Access conventions.
- Keep Sovereign unavailable unless exact published binaries pass the complete runtime matrix, including positive named routing, negative networking, native guest startup and credential lifecycle. A matching fresh receipt and observed guest confinement are both required.
- Public preview versions must carry an alpha suffix in the manifest, tag, and release notes. Keep unfinished tracks visibly unavailable; a public preview does not satisfy their stable-release gates.
- Stage exact files for commits; shared files have serial ownership handoffs across plans.

## Work Guidance

- Read this file and any closer `AGENTS.md` before editing a target.
- Keep changes focused and update the closest owning documentation after meaningful behavior changes.
- Record upstream Agent Zero/SAM revisions, drift, adaptations, tests, and release-posture effects in `docs/compatibility.md`.
- Use `/opt/venv-a0/bin/python` for Agent Zero framework/plugin integration checks and the project test environment for standalone unit tests.

## Verification

- Run targeted tests after each task, adjacent tests after each track, and the three verification passes defined by the approved specification.
- Run static checks, exact schema/transport contracts, adversarial tests, secret scans, performance gates, lifecycle exercises, and clean-checkout validation before release claims.
- Never weaken a failing security test. Unsupported capabilities must remain visibly gated.

## Child DOX Index

No child contracts are required initially. Add one only when a subtree gains a durable, distinct workflow that cannot be expressed concisely here.
