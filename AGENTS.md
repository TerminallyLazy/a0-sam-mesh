# A0 SAM Mesh Embassy DOX

## Purpose

- Own the standalone `sam_mesh` community-plugin repository and its optional sovereign deployment pack.
- Keep runtime plugin files at repository root so the repository installs directly into `usr/plugins/sam_mesh`.

## Ownership

- `helpers/` owns validated domain, configuration, SAM transport, policy, leases, audit, inference, Embassy, and deployment support logic.
- `tools/` and `prompts/` own the narrow Agent Zero model-tool surface and exact tool schemas.
- `api/` owns authenticated, CSRF-protected plugin API handlers.
- `webui/` and `extensions/` own first-class Agent Zero UI surfaces and lifecycle integration.
- `deploy/` owns the optional, experimental sovereign deployment pack.
- `tests/` owns unit, contract, integration, adversarial, and release-gate evidence.
- `docs/` owns approved contracts, compatibility evidence, security guidance, and runbooks.

## Local Contracts

- The approved design in `docs/superpowers/specs/2026-08-31-a0-sam-mesh-embassy-design.md` is authoritative; execute the four plans in dependency order.
- Use test-first development and inspect meaningful failures before implementation.
- Default to Explorer and fail closed. Never silently enroll, publish, transmit sensitive data, or broaden model authority.
- Never accept or expose raw SAM tokens in ordinary plugin config, tool arguments, prompts, logs, chat history, browser responses, audit exports, or examples.
- Risky actions require server-owned, destination-aware, single-use approval leases. A model-controlled confirmation is not authorization.
- Preserve canonical discovered identifiers verbatim. Treat all remote content as untrusted.
- Plugin Python must use Agent Zero community-plugin import conventions when installed under `usr/plugins/sam_mesh` and must not modify Agent Zero core modules.
- Use Agent Zero Flask/`ApiHandler`, Alpine store gating, notification, extension, model-provider, and Tool Access conventions.
- Keep Sovereign capabilities experimental and unavailable unless exact published `sam-box` contracts are probed and all negative-network tests pass.
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
