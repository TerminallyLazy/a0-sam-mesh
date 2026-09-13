# SAM Mesh stable completion

The approved Embassy design and the four 2026-08-31 implementation plans remain the feature contract. This plan completes their outstanding release gates against released SAM v0.1.0-alpha.9 and current main, preserving the native Agent Zero plugin layout and default Explorer mode.

### Task 1: Complete the Sovereign boundary

Implement and verify the deployment pack using the published `sam-box` and `nano-init` binaries. Replace the obsolete tun2socks assumption with nano-init's actual bundled tun2connect contract. Agent Zero must have no ordinary network interface or node credential/socket; only the boundary UDS and separate WebUI UDS are mounted. Use verified issuer/audience credentials, default-deny named egress, a working ingress-only UI bridge, and bounded expiry/restart/drain/rollback behavior. Probe actual TUN, denied DNS/UDP/literal IP and administrative paths, allowed named destinations, socket separation, and missing/expired credentials in disposable containers. Never treat CLI flags as certification. Read the Sovereign plan's five tasks for exact constraints and limits; document evidence and adaptations. Keep capability unavailable if a required runtime proof fails. Own deploy/, helpers/sovereign.py, tests/test_sovereign.py, docs/sovereign-operations.md only. Do not change shared UI, config, version or release docs. Write meaningful failing tests before implementation. No host dependency installs or modifications to existing user containers. No subagents.

### Task 2: Complete authenticated Embassy publication

Implement the bounded three-tool MCP broker, authenticated origin transport, native protected publication/status/drain/close API and lifecycle integration. Preserve project/profile and origin isolation, limits, cleanup, and explicit human publication acknowledgment. Verify the final hop against real SAM, including spoof rejection. Integrate selectable Embassy and validated Sovereign modes with native UI. No core Agent Zero modifications, raw credentials in ordinary configuration, or undocumented SAM registration endpoints.

### Task 3: Certify live mesh and native model execution

Exercise real separately enrolled peers, discovery, remote MCP tools, inference catalog and actual model completion through Agent Zero's native response-tool loop. Exercise Embassy origin isolation, publication withdrawal and restarts and Sovereign network matrix. Record exact released and current SAM revisions, binaries, commands, sanitized receipts, failures and resolutions. Use only isolated test identities and benign prompts. Mock outputs do not satisfy live model acceptance.

### Task 4: Review and publish stable

Run focused tests for changes followed by full framework, native install/uninstall, JavaScript, static, security and hosted CI checks. Independently review implementation and exact final diff. Update public documentation and stable version only after required evidence passes, create reproducible package, commit and push, publish the stable release with checksums and verification evidence, and update the existing community Plugin Index contribution following current instructions. Verify public assets and current-head CI; distinguish maintainer acceptance from submission.
