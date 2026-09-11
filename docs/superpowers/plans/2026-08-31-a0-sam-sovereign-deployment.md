# A0 SAM Sovereign Deployment Pack Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Provide an optional, fail-closed deployment where Agent Zero has no general network interface and all named TCP egress crosses a capability-gated `sam-box` boundary.

**Architecture:** One host-level `sam-node` owns mesh identity; one `sam-box` owns the Agent Zero sandbox boundary. Agent Zero runs with `network_mode: none`, a TUN device, and a bind-mounted sandbox-facing UDS; a separate host-facing UI bridge reaches Agent Zero through a dedicated UDS without granting general egress.

**Tech Stack:** Docker Compose, `sam-node`, `sam-box`, tun2socks, Unix-domain sockets, YAML agent bundles, shell/Python health checks, pytest, Bats, container security tests.

**Spec:** `docs/superpowers/specs/2026-08-31-a0-sam-mesh-embassy-design.md`

## Global Constraints

- This pack is optional and labeled experimental until the required `sam-box` behavior exists in a published SAM release.
- Agent Zero uses `network_mode: none`; proxy environment variables are not treated as confinement.
- `sam-box` receives the node UDS; Agent Zero receives only the sandbox-facing `sam-box` UDS.
- Agent Zero never receives the SAM node token or node socket.
- Allowed egress is matched by requested name; empty allowlist means no external internet destination.
- `mesh.sam.alt` exposes only `/v1/models`, `/v1/chat/completions`, `/v1/completions`, and `/mcp`.
- UDP and direct DNS egress are denied.
- Current SAM gaps—secret injection, ingress reverse channel, and credential rotation—remain disabled or fail closed.
- Sovereign Embassy ingress is disabled until the reverse channel is implemented and capability-probed.
- WebUI reachability uses a dedicated UDS bridge and never adds a general network interface to Agent Zero.
- Rollback restores the ordinary community-plugin deployment without deleting SAM node identity.

---

## File map

| Path | Responsibility |
|---|---|
| `deploy/compose/docker-compose.sovereign.yml` | Sandbox/node/box/UI bridge topology |
| `deploy/compose/.env.example` | Non-secret image/path/port settings |
| `deploy/sam-node/sam-node.yaml` | No-service/default-deny node configuration |
| `deploy/sam-box/agent-bundle.yaml` | Agent identity, egress, and disabled ingress |
| `deploy/policies/egress-allow.txt` | Explicit named external destinations |
| `deploy/scripts/check-capabilities.py` | Required binary/help/runtime probes |
| `deploy/scripts/start-sandbox-network.sh` | TUN/tun2socks bootstrap and route checks |
| `deploy/scripts/ui-bridge.sh` | Loopback-to-UDS bridge inside sandbox namespace |
| `deploy/healthchecks/*.sh` | Node, box, agent, and policy health |
| `deploy/tests/*` | Compose, egress, DNS, UI, restart, and rollback tests |

### Task 1: Implement the `sam-box` capability gate

**Files:**
- Create: `deploy/scripts/check-capabilities.py`
- Create: `deploy/tests/test_capability_gate.py`
- Create: `deploy/README.md`

**Interfaces:**
- Produces: `CapabilityGateReport` JSON and exit status 0 only when the exact required surface exists.

- [ ] **Step 1: Write failing help-surface tests**

```python
REQUIRED_SAM_BOX_FLAGS = {
    "--socket", "--sidecar-socket", "--bundle",
    "--credential-issuer", "--credential-audience", "--egress-allow",
}


def test_gate_rejects_missing_required_flag(tmp_path):
    help_text = "sam-box run --socket --sidecar-socket --bundle"
    report = inspect_sam_box_help(help_text)
    assert report.supported is False
    assert "--credential-issuer" in report.missing_flags


def test_gate_refuses_documented_unimplemented_features():
    report = evaluate_requested_features({"secret_injection": True, "ingress": True})
    assert report.blockers == ["secret_injection_unavailable", "ingress_reverse_channel_unavailable"]
```

- [ ] **Step 2: Verify failure**

Run: `pytest deploy/tests/test_capability_gate.py -v`  
Expected: FAIL because the checker does not exist.

- [ ] **Step 3: Implement the gate**

Run `sam-node --version`, `sam-box run --help`, verify the required flags, verify node/box socket directories are owned by the configured host UID and not group/world writable, and probe `mesh.sam.alt` path restrictions through a test box. Emit machine-readable `supported`, `binary_versions`, `missing_flags`, `blockers`, and `warnings`.

- [ ] **Step 4: Document the explicit experimental boundary**

`deploy/README.md` must state that secret injection, reverse-channel ingress, and credential rotation are disabled; `--insecure-unverified-bundle` is refused by the standard profile; and the pack does not start when the gate fails.

- [ ] **Step 5: Run tests and commit**

Run: `pytest deploy/tests/test_capability_gate.py -v`  
Expected: PASS.

```bash
git add deploy/scripts/check-capabilities.py deploy/tests/test_capability_gate.py deploy/README.md
git commit -m "feat: gate sovereign mode on verified sam-box capabilities"
```

### Task 2: Define the default-deny Compose and socket topology

**Files:**
- Create: `deploy/compose/docker-compose.sovereign.yml`
- Create: `deploy/compose/.env.example`
- Create: `deploy/sam-node/sam-node.yaml`
- Create: `deploy/sam-box/agent-bundle.yaml`
- Create: `deploy/policies/egress-allow.txt`
- Create: `deploy/tests/test_compose_contract.py`

**Interfaces:**
- Produces: services `sam-node`, `sam-box-a0`, `agent-zero`, and `a0-ui-gateway` with separate node/agent/UI socket volumes.

- [ ] **Step 1: Write failing topology tests**

```python
def test_agent_has_no_network_or_node_credential(compose):
    a0 = compose["services"]["agent-zero"]
    assert a0["network_mode"] == "none"
    assert "/dev/net/tun" in a0["devices"]
    assert "NET_ADMIN" in a0["cap_add"]
    rendered = json.dumps(a0)
    assert "node.sock" not in rendered
    assert "SAM_API_TOKEN" not in rendered


def test_sam_box_is_only_holder_of_both_sockets(compose):
    box = json.dumps(compose["services"]["sam-box-a0"])
    assert "/run/sam-node/node.sock" in box
    assert "/run/sam-agent/agent.sock" in box
```

- [ ] **Step 2: Verify failure**

Run: `pytest deploy/tests/test_compose_contract.py -v`  
Expected: FAIL.

- [ ] **Step 3: Create strict node and bundle configuration**

```yaml
# deploy/sam-node/sam-node.yaml
version: "v1alpha1"
services: []
attenuation:
  policies:
    - 'deny if false;'
```

```yaml
# deploy/sam-box/agent-bundle.yaml
id: a0-default
external_id: a0-default
egress: []
ingress: []
```

The production bundle is generated by the platform with its credential; the checked-in sample contains no credential and cannot start outside the test profile.

- [ ] **Step 4: Create Compose services**

`sam-node` mounts only `node-socket` and node state. `sam-box-a0` mounts node socket read/write, creates `agent-socket` mode 0600, and runs with verified bundle/issuer/audience arguments. `agent-zero` uses `network_mode: none`, mounts only `agent-socket` and `ui-socket`, receives `/dev/net/tun`, and starts through `start-sandbox-network.sh`. `a0-ui-gateway` publishes `${A0_UI_PORT:-50080}` and connects only to `ui.sock`.

- [ ] **Step 5: Validate Compose and commit**

Run: `docker compose -f deploy/compose/docker-compose.sovereign.yml config --quiet && pytest deploy/tests/test_compose_contract.py -v`  
Expected: Compose valid and tests PASS.

```bash
git add deploy/compose deploy/sam-node deploy/sam-box deploy/policies deploy/tests/test_compose_contract.py
git commit -m "feat: define sovereign agent zero socket topology"
```

### Task 3: Bootstrap the networkless sandbox and prove named egress policy

**Files:**
- Create: `deploy/scripts/start-sandbox-network.sh`
- Create: `deploy/healthchecks/sandbox-policy.sh`
- Create: `deploy/tests/egress.bats`
- Create: `deploy/tests/dns_exfiltration.bats`

**Interfaces:**
- Produces: TUN interface `tun0`, virtual-DNS routing through tun2socks, and a hard precondition before Agent Zero starts.

- [ ] **Step 1: Write failing negative-path tests**

```bash
@test "unapproved domain is refused" {
  run docker compose exec -T agent-zero curl -fsS --connect-timeout 3 https://example.com/
  [ "$status" -ne 0 ]
}

@test "mesh facade is reachable by name" {
  run docker compose exec -T agent-zero curl -fsS http://mesh.sam.alt/v1/models
  [ "$status" -eq 0 ]
}

@test "guest has no ordinary ethernet interface" {
  run docker compose exec -T agent-zero sh -c 'ip -o link | cut -d: -f2'
  [[ "$output" == *" lo"* ]]
  [[ "$output" == *" tun0"* ]]
  [[ "$output" != *"eth0"* ]]
}
```

- [ ] **Step 2: Run tests to confirm failure**

Run: `bats deploy/tests/egress.bats deploy/tests/dns_exfiltration.bats`  
Expected: FAIL before network bootstrap exists.

- [ ] **Step 3: Implement bootstrap with pinned tun2socks CLI contract**

The script verifies `network_mode=none` by asserting no `eth*` interface, creates `tun0`, starts the repository-pinned tun2socks binary against `/run/sam-agent/agent.sock`, installs the default route only through `tun0`, waits for `mesh.sam.alt/v1/models`, and then `exec`s Agent Zero. It exits before Agent Zero if any invariant fails. Capture the exact tun2socks flags in a versioned `deploy/tun2socks-version.txt` after testing the selected binary; the capability gate checks that version before invoking the script.

- [ ] **Step 4: Add DNS and protocol negative tests**

Attempt UDP DNS to public resolvers, raw TCP to a literal public IP, an unapproved hostname, an approved hostname, `mesh.sam.alt`, and a named mesh MCP service. Expected: only approved hostnames and mesh names succeed; UDP and literal-IP bypass fail.

- [ ] **Step 5: Run tests and commit**

Run: `bats deploy/tests/egress.bats deploy/tests/dns_exfiltration.bats`  
Expected: PASS.

```bash
git add deploy/scripts/start-sandbox-network.sh deploy/healthchecks/sandbox-policy.sh deploy/tests deploy/tun2socks-version.txt
git commit -m "feat: enforce named egress for networkless agent zero"
```

### Task 4: Preserve Agent Zero WebUI access without restoring egress

**Files:**
- Create: `deploy/scripts/ui-bridge.sh`
- Create: `deploy/healthchecks/ui.sh`
- Create: `deploy/tests/ui_bridge.bats`
- Modify: `deploy/compose/docker-compose.sovereign.yml`

**Interfaces:**
- Produces: `/run/a0-ui/ui.sock` and host-facing `${A0_UI_PORT}` through an ingress-only gateway.

- [ ] **Step 1: Write failing reachability and escape tests**

```bash
@test "host reaches agent zero through UI socket gateway" {
  run curl -fsS "http://127.0.0.1:${A0_UI_PORT}/health"
  [ "$status" -eq 0 ]
}

@test "UI gateway cannot reach arbitrary internet" {
  run docker compose exec -T a0-ui-gateway curl -fsS --connect-timeout 3 https://example.com/
  [ "$status" -ne 0 ]
}
```

- [ ] **Step 2: Verify failure**

Run: `bats deploy/tests/ui_bridge.bats`  
Expected: FAIL.

- [ ] **Step 3: Implement the ingress-only bridge**

Inside the Agent Zero namespace, `ui-bridge.sh` listens on the bind-mounted UDS and forwards only to Agent Zero's loopback WebUI port. `a0-ui-gateway` has a published host port, no SAM/node socket, a read/write UI-socket mount, read-only filesystem, dropped capabilities, and a seccomp/no-new-privileges profile. It forwards only HTTP/WebSocket traffic to the UDS.

- [ ] **Step 4: Prove separation**

Assert the gateway cannot open the agent socket or node socket, cannot resolve/reach external hosts, and cannot write Agent Zero data. Assert Agent Zero still has no `eth0` after UI access succeeds.

- [ ] **Step 5: Run tests and commit**

Run: `bats deploy/tests/ui_bridge.bats && docker compose -f deploy/compose/docker-compose.sovereign.yml config --quiet`  
Expected: PASS.

```bash
git add deploy/scripts/ui-bridge.sh deploy/healthchecks/ui.sh deploy/tests/ui_bridge.bats deploy/compose/docker-compose.sovereign.yml
git commit -m "feat: add ingress-only webui bridge for sovereign mode"
```

### Task 5: Add lifecycle, credential-expiry, rollback, and security certification

**Files:**
- Create: `deploy/scripts/preflight.sh`
- Create: `deploy/scripts/drain.sh`
- Create: `deploy/scripts/rollback.sh`
- Create: `deploy/upgrade/compatibility.yaml`
- Create: `deploy/tests/lifecycle.bats`
- Create: `deploy/tests/security.bats`
- Create: `docs/sovereign-operations.md`
- Modify: `docs/compatibility.md`

**Interfaces:**
- Produces: preflight/start/drain/rollback operator contract and signed-off negative test report.

- [ ] **Step 1: Write failing lifecycle tests**

Test clean start, node restart, box restart, Agent Zero restart, credential approaching expiry, missing credential, socket permission change, emergency disconnect, and rollback. Missing/expired credentials must stop or drain the box; they must never select `--insecure-unverified-bundle` automatically.

- [ ] **Step 2: Implement preflight and drain**

`preflight.sh` runs the capability checker, validates bundle/credential issuer and audience, socket owners/modes, Compose contract, image digests, and UI port availability. `drain.sh` disables plugin remote features, stops accepting new work, then stops Agent Zero, box, and node in that order while preserving node state.

- [ ] **Step 3: Implement recoverable rollback**

`rollback.sh` requires an explicit ordinary Compose file path, exports redacted plugin settings/audit, stops the sovereign stack, starts the ordinary stack with the same `usr` volume, and leaves SAM identity/state untouched. It never deletes volumes or runs `sam-node reset`.

- [ ] **Step 4: Run the security certification**

Run: `pytest deploy/tests -v && bats deploy/tests/*.bats`  
Expected: all positive and negative tests PASS, including zero unapproved egress and WebUI reachability.

- [ ] **Step 5: Record supported versions and known gaps**

`deploy/upgrade/compatibility.yaml` records exact Agent Zero image digest, SAM tag/SHA, sam-box help hash, tun2socks version/hash, tested kernel/Docker versions, and the three disabled gaps. `docs/sovereign-operations.md` documents preflight, startup, status, emergency closure, rotation limitation, drain, upgrade, and rollback.

- [ ] **Step 6: Commit**

```bash
git add deploy/scripts deploy/upgrade deploy/tests docs/sovereign-operations.md docs/compatibility.md
git commit -m "test: certify sovereign deployment lifecycle and network boundary"
```

## Sovereign release gate

Sovereign remains experimental until all container negative tests demonstrate no unapproved named TCP egress, direct DNS/UDP/literal-IP bypass fails, Agent Zero never receives the node socket/token, the WebUI bridge does not restore egress, missing/expired credentials fail closed, rollback preserves user and SAM identity state, and the required `sam-box` contracts exist in a published SAM release.

## Current execution assessment

The 2026-09-10 task and release-gate assessment is in [release-readiness](../../release-readiness.md). Historical step checkboxes remain unclaimed where live certification or the planned commit boundary has not occurred. Implementation adaptations and exact source revisions are recorded in [compatibility](../../compatibility.md).
