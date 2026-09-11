# Community preview release assessment

**Version: 1.0.0-alpha.1 · 2026-09-11**

SAM Mesh is published as a native Agent Zero community preview. The alpha version in
`plugin.yaml`, the Git tag, and the release notes identifies the same scope. This release
makes the implemented plugin available for evaluation; it does not certify the complete
Embassy/Sovereign design or an enrolled production mesh.

## Available and unavailable tracks

| Track | Implemented | Release posture |
| --- | --- | --- |
| Core / Observatory | Scoped passports, connected-peer TCP and pinned UDS, schema validation, unknown-risk approvals, encrypted decisions, audit, nine native tools, local disconnect/resume, and the Observatory | Available in the alpha; Explorer is the default and grants no execution authority |
| Cognitive Relay | Native provider, pinned client, admission and quotas, automatic-route disclosure, public probes, and one-use named-route approvals | Available for evaluation; real-model and enrolled-mesh certification remains pending |
| Embassy | Declaration validation, broker/session components, tool-boundary helpers, and withdrawal-before-stop state machine | Unavailable; authenticated final-hop integration, applied SAM registration, and live host isolation are incomplete |
| Sovereign | Capability report and experimental deployment draft | Unavailable; bootstrap/translator, UI ingress, and negative-network certification are incomplete |
| Native MCP / Raw MCP | Read-only compatibility assessment | Registration and raw gateway execution remain unavailable because the host's disabled-tool list cannot deny future unknown gateway tools |

Unavailable modes are disabled in native settings and remain blocked by backend capability
checks. Saving settings cannot enroll a node or advertise a service. The approved design and
its four plans remain in `docs/superpowers/`; their unmet gates are not marked complete.

## Verification

Native integration is checked against upstream Agent Zero
`b1cbd1f960a1a5c4482b324dcff4742aa67b7a51` with framework Python 3.12.4 in a disposable,
network-disconnected runtime. The package uses the normal ZIP installer and installed
community namespace. Authentication, CSRF, config inheritance, hooks, tools, prompts,
provider discovery, assets, independent activation, offline stop, and uninstall are covered.
The source hash check covers all 3,034 upstream framework files; no core patch is required.

The release includes a machine-readable verification receipt alongside its ZIP and SHA-256
checksums. The complete Python suite includes the audit-retention tests; five JavaScript
behavior tests cover scope changes, stale responses, protected-data cleanup, and modal
ownership. Ruff and the repository's secret-pattern scan are release checks. Before the
first public push, all 104 historical Git blobs were also scanned with zero pattern findings.
These scans do not prove that arbitrary text can never contain a secret.

CI runs the full suite and native ZIP verification on both the pinned framework revision
and current upstream `main`. Its runtime image is pinned by digest, and test traffic is
restricted to the container's local test fixtures after tooling setup.

## Stable release gates

- Exercise Explorer, remote discovery/preflight/approval/dispatch, TCP and UDS against the
  supported SAM release and current-main binary matrix, including restarts and revocation.
- Exercise native inference through a complete Agent Zero response-tool loop with actual
  supported models on an enrolled mesh, covering streaming, function calls and errors.
- Integrate and test an authenticated SAM-to-Embassy origin boundary, administrator-applied
  service registration, malicious-caller isolation, draining, withdrawal, and rollback.
- Complete Sovereign runtime/bootstrap/ingress integration using the exact published
  `sam-box` contracts and pass negative-network and credential-lifecycle tests.

No live enrolled SAM node or real-model credentials were used for the alpha verification.
Generic host model-search traffic is outside this plugin's pinned transport: use the
Observatory catalog and project-secret reference as described in the README.

## Publication

The standalone [repository](https://github.com/TerminallyLazy/a0-sam-mesh) contains the root
manifest, README, MIT license, generated logo, source, tests, and operating documentation.
The [alpha release](https://github.com/TerminallyLazy/a0-sam-mesh/releases/tag/v1.0.0-alpha.1)
contains the installable archive and verification assets.

The Plugin Index submission contains only `plugins/sam_mesh/index.yaml` and its square,
8,108-byte `thumbnail.webp`. The index name matches the remote manifest. Index availability
requires the upstream maintainers to review and merge the contribution; publishing the
repository or release does not by itself make the plugin appear in the index.
