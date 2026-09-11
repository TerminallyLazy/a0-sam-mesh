# A0 SAM Core and Mesh Observatory Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the installable community plugin, runtime capability probes, Capability Passport, Delegation Gate, approval leases, audit log, native SAM tools, and Mesh Observatory.

**Architecture:** The plugin uses a plugin-owned SAM Streamable HTTP client so it can enforce project/profile policy and support both TCP and UDS. Agent Zero's native MCP client remains an optional read-only surface; risky remote execution flows only through the Delegation Gate.

**Tech Stack:** Agent Zero plugin APIs, Python async, `httpx`, MCP Streamable HTTP JSON/event-stream framing, SQLite, FastAPI/Starlette-compatible Agent Zero handlers, Alpine.js, pytest, pytest-asyncio.

**Spec:** `docs/superpowers/specs/2026-08-31-a0-sam-mesh-embassy-design.md`

## Global Constraints

- Plugin name is exactly `sam_mesh`; community repository runtime files stay at repository root.
- Fresh installs use `explorer`; remote execution, inference, inbound publication, and raw MCP are disabled.
- Support TCP Streamable HTTP and HTTP over UDS; never implement a bare JSON-RPC socket protocol.
- Never persist a raw node token in plugin config, tool arguments, prompts, logs, audit exports, or chat history.
- Direct `call_remote_tool`, peer connection, pubsub, network-info, and recent-log MCP tools are disabled in safe modes.
- Capability support comes from runtime health, MCP initialize, `tools/list`, and exact schemas—not the MCP implementation version.
- Canonical SAM tool URIs are retained verbatim.
- Mutation calls require single-use leases and receive no extra plugin retry.
- A schema, destination, passport, profile, or data-class change invalidates an existing lease.
- `a2a`, semantic intent search, real peer messaging, and full OpenAI compatibility are not claimed.
- Target Agent Zero compatibility begins at audited commit `6a6cecff8527b164668c7a6ab2f76b6b1ed7cfa1`; CI also tests supported main.
- SAM matrix begins with `v0.1.0-alpha.7` and audited commit `3224aae8dc962d6e8d4a83c4fa1f2d3e84c6db0f`.

---

## File map

| Path | Responsibility |
|---|---|
| `plugin.yaml`, `default_config.yaml`, `requirements.txt` | Plugin manifest, fail-closed defaults, dependencies |
| `helpers/domain.py` | Enums and immutable domain records |
| `helpers/config.py` | Scoped configuration, secret/token-file resolution, validation |
| `helpers/mcp_transport.py` | MCP Streamable HTTP session over TCP or UDS |
| `helpers/sam_client.py` | Typed SAM health, tools, models, and calls |
| `helpers/capabilities.py` | Runtime feature probes and compatibility report |
| `helpers/passport.py` | Passport validation, matching, and version hashes |
| `helpers/risk.py` | Deterministic tool/data risk classification |
| `helpers/leases.py` | Approval lease issue/consume/revoke |
| `helpers/audit.py` | Redacted append-only SQLite audit chain |
| `helpers/gate.py` | Preflight and invocation orchestration |
| `tools/*.py`, `prompts/*.md` | Agent-visible capabilities and exact schemas |
| `api/*.py` | Authenticated status, catalog, preflight, approval, audit APIs |
| `webui/*`, `extensions/webui/*` | Settings card and right-canvas Observatory |
| `execute.py` | Short idempotent diagnostics only |
| `tests/*` | Unit, contract, Agent Zero integration, and adversarial tests |

### Task 1: Establish the community-plugin contract and test harness

**Files:**
- Create: `plugin.yaml`
- Create: `default_config.yaml`
- Create: `requirements.txt`
- Create: `pyproject.toml`
- Create: `tests/conftest.py`
- Create: `tests/test_manifest.py`
- Create: `.github/workflows/test.yml`

**Interfaces:**
- Produces: a discoverable `sam_mesh` plugin and `a0_checkout` pytest fixture used by all later integration tests.

- [ ] **Step 1: Write the failing manifest test**

```python
from pathlib import Path
import yaml


def test_manifest_is_installable_and_fail_closed():
    root = Path(__file__).parents[1]
    manifest = yaml.safe_load((root / "plugin.yaml").read_text())
    defaults = yaml.safe_load((root / "default_config.yaml").read_text())
    assert manifest == {
        "name": "sam_mesh",
        "title": "A0 SAM Mesh Embassy",
        "description": "Governed SAM tools, mesh inference, and optional sovereign Agent Zero service publication.",
        "version": "1.0.0",
        "settings_sections": ["mcp", "external"],
        "per_project_config": True,
        "per_agent_config": True,
        "always_enabled": False,
    }
    assert defaults["schema"] == "a0.sam.config/v1alpha1"
    assert defaults["passport"]["mode"] == "explorer"
    assert defaults["features"] == {
        "remote_calls": False,
        "mesh_inference": False,
        "inbound_publication": False,
        "raw_mcp": False,
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/test_manifest.py -v`  
Expected: FAIL because `plugin.yaml` and `default_config.yaml` do not exist.

- [ ] **Step 3: Create the manifest and fail-closed defaults**

```yaml
# default_config.yaml
schema: a0.sam.config/v1alpha1
transport:
  type: uds
  base_url: http://127.0.0.1:8080
  socket_path: /var/run/sam/node.sock
  token_secret_name: ""
  token_file: ""
passport:
  schema: a0.sam.passport/v1alpha1
  mode: explorer
  outbound:
    max_data_class: public
    allow_services: []
    deny_tools: ["*"]
    remote_mutations: deny
  inference:
    enabled: false
    route_mode: automatic
    required_labels: []
    sensitive_data: deny
  limits:
    calls_per_session: 0
    discovery_timeout_seconds: 30
    timeout_seconds: 90
    approval_lease_minutes: 15
  inbound:
    enabled: false
    services: []
features:
  remote_calls: false
  mesh_inference: false
  inbound_publication: false
  raw_mcp: false
```

Set `requirements.txt` to `httpx>=0.27,<1` only; Agent Zero supplies MCP, FastMCP, SQLite, and its UI runtime. Configure `pyproject.toml` with pytest asyncio mode `auto` and Ruff line length 100.

- [ ] **Step 4: Add the Agent Zero checkout fixture and CI matrix**

`tests/conftest.py` must symlink the repository into `<checkout>/usr/plugins/sam_mesh` for integration-marked tests and remove only that symlink afterward. CI clones the audited commit and current `main`, installs `requirements.txt` plus Agent Zero dev requirements, and runs unit tests on both.

- [ ] **Step 5: Run the contract tests**

Run: `pytest tests/test_manifest.py -v`  
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add plugin.yaml default_config.yaml requirements.txt pyproject.toml tests .github/workflows/test.yml
git commit -m "chore: establish sam mesh community plugin contract"
```

### Task 2: Implement domain records and scoped configuration

**Files:**
- Create: `helpers/__init__.py`
- Create: `helpers/domain.py`
- Create: `helpers/config.py`
- Create: `tests/test_config.py`

**Interfaces:**
- Produces: `OperatingMode`, `DataClass`, `RiskLevel`, `RouteMode`, `ProbeStatus`, `ResolvedConfig`, `CapabilityPassport`, `ToolDescriptor`, `PreflightDecision`, and `resolve_config(agent) -> ResolvedConfig`.

- [ ] **Step 1: Write failing validation tests**

```python
def test_config_rejects_raw_token_and_unmounted_socket(fake_agent, plugin_config):
    plugin_config["transport"]["token"] = "secret"
    with pytest.raises(ConfigError, match="raw token"):
        resolve_config(fake_agent, raw=plugin_config)

    plugin_config["transport"].pop("token")
    plugin_config["transport"]["socket_path"] = "/tmp/attacker.sock"
    with pytest.raises(ConfigError, match="allowed socket roots"):
        resolve_config(fake_agent, raw=plugin_config, allowed_socket_roots=("/var/run/sam",))


def test_config_normalizes_any_of_labels(fake_agent, plugin_config):
    plugin_config["passport"]["inference"]["required_labels"] = ["region=us", "phi=false"]
    cfg = resolve_config(fake_agent, raw=plugin_config)
    assert cfg.passport.inference.required_labels == ("region=us", "phi=false")
    assert cfg.passport.inference.label_semantics == "any_of"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_config.py -v`  
Expected: FAIL with missing `helpers.domain` and `helpers.config`.

- [ ] **Step 3: Implement immutable enums and records**

Use `StrEnum` and frozen dataclasses. `ResolvedConfig` must contain transport, resolved credential, passport, features, and scope. `CapabilityPassport.version_hash()` returns SHA-256 over canonical JSON with sorted keys and compact separators.

```python
@dataclass(frozen=True)
class TransportConfig:
    type: Literal["http", "uds"]
    base_url: str
    socket_path: str | None
    token: str | None


@dataclass(frozen=True)
class Scope:
    project_name: str
    agent_profile: str
    chat_id: str
```

- [ ] **Step 4: Implement fail-closed resolution**

`resolve_config` must call `helpers.plugins.get_plugin_config("sam_mesh", agent=agent)`, reject unknown top-level keys, accept credentials only through `token_secret_name` resolved with `get_secrets_manager(agent.context)` or a mode-0600 token file, and reject HTTP URLs that contain userinfo, fragments, or non-HTTP schemes. Disable features that contradict the selected operating mode.

- [ ] **Step 5: Run tests and static checks**

Run: `pytest tests/test_config.py -v && ruff check helpers tests/test_config.py`  
Expected: PASS with no Ruff findings.

- [ ] **Step 6: Commit**

```bash
git add helpers tests/test_config.py
git commit -m "feat: add fail-closed sam configuration and domain model"
```

### Task 3: Build the TCP/UDS MCP transport and capability probe

**Files:**
- Create: `helpers/mcp_transport.py`
- Create: `helpers/sam_client.py`
- Create: `helpers/capabilities.py`
- Create: `tests/fakes/sam_sidecar.py`
- Create: `tests/test_sam_transport.py`
- Create: `tests/test_capabilities.py`

**Interfaces:**
- Consumes: `TransportConfig`, `ToolDescriptor`, `ProbeStatus`.
- Produces: `McpStreamableSession`, `SamClient`, `CapabilityProbe.probe() -> CompatibilityReport`.

- [ ] **Step 1: Write failing transport contract tests**

```python
@pytest.mark.asyncio
async def test_mcp_session_preserves_session_id_and_calls_tools(fake_sidecar, http_config):
    client = SamClient(http_config)
    report = await client.initialize_mcp()
    result = await client.call_mcp_tool("get_mesh_info", {})
    assert report.server_name == "sam-node"
    assert result.structured["connected"] is True
    assert fake_sidecar.received_headers[1]["mcp-session-id"] == "session-123"


@pytest.mark.asyncio
async def test_uds_uses_http_over_socket(uds_sidecar, uds_config):
    client = SamClient(uds_config)
    assert (await client.health()).ready is True
    assert uds_sidecar.tcp_connections == 0
```

- [ ] **Step 2: Run tests to verify failure**

Run: `pytest tests/test_sam_transport.py tests/test_capabilities.py -v`  
Expected: FAIL because the transport/client classes do not exist.

- [ ] **Step 3: Implement Streamable HTTP framing**

`McpStreamableSession` sends `initialize`, then `notifications/initialized`, retains `Mcp-Session-Id`, and supports JSON or `text/event-stream` responses. It sets `Accept: application/json, text/event-stream`, `Content-Type: application/json`, a 4 MiB MCP response limit, and never follows redirects. UDS uses `httpx.AsyncHTTPTransport(uds=socket_path)`.

```python
async def call_tool(self, name: str, arguments: dict) -> dict:
    return await self.request("tools/call", {"name": name, "arguments": arguments})
```

Map 401 to `SamAuthRequired`, 403 to `SamAuthRejected` or `SamPolicyDenied`, 503 to `SamNodeNotReady`, transport failures to `SamConnectivityError`, and malformed schemas to `SamSchemaError`.

- [ ] **Step 4: Implement exact capability probes**

Probe `/healthz`, `/readyz`, MCP initialize, `tools/list`, and `/v1/models`. Mark each expected read tool independently. Validate that `call_remote_tool.arguments` is an object and `required_labels` is a string when those tools exist. Record extra tools without enabling them.

- [ ] **Step 5: Run contract tests**

Run: `pytest tests/test_sam_transport.py tests/test_capabilities.py -v`  
Expected: PASS for TCP, UDS, JSON, event-stream, auth, partial discovery, and schema mismatch cases.

- [ ] **Step 6: Commit**

```bash
git add helpers tests/fakes tests/test_sam_transport.py tests/test_capabilities.py
git commit -m "feat: add sam streamable http transport and capability probes"
```

### Task 4: Implement Capability Passport matching and deterministic risk classification

**Files:**
- Create: `helpers/passport.py`
- Create: `helpers/risk.py`
- Create: `tests/test_passport.py`
- Create: `tests/test_risk.py`

**Interfaces:**
- Consumes: `CapabilityPassport`, `ToolDescriptor`, call arguments.
- Produces: `PassportDecision evaluate(passport, descriptor, data_class)` and `RiskAssessment classify(descriptor, arguments)`.

- [ ] **Step 1: Write the failing policy tests**

```python
def test_deny_beats_allow_and_unknown_requires_approval(passport, tool):
    passport = replace(passport, allow_services=("mcp://finance/*",), deny_tools=("*/delete-*",))
    tool = replace(tool, canonical_uri="mcp://finance/delete-account")
    assert evaluate(passport, tool, DataClass.PUBLIC).outcome == "deny"

    unknown = replace(tool, canonical_uri="mcp://finance/reconcile", annotations={})
    risk = classify(unknown, {"account": "x"})
    assert risk.level is RiskLevel.UNKNOWN
    assert risk.requires_single_use_lease is True


def test_data_class_escalation_is_denied(passport, tool):
    passport = replace(passport, max_data_class=DataClass.INTERNAL)
    assert evaluate(passport, tool, DataClass.CONFIDENTIAL).outcome == "deny"
```

- [ ] **Step 2: Verify failure**

Run: `pytest tests/test_passport.py tests/test_risk.py -v`  
Expected: FAIL with missing modules.

- [ ] **Step 3: Implement URI matching and precedence**

Use `fnmatchcase` on canonical URIs. Apply precedence: explicit deny, data-class ceiling, mode/feature gate, allow rule, then deny by default. Required labels are serialized exactly once as a comma-separated any-of string.

- [ ] **Step 4: Implement conservative risk evidence**

Honor MCP annotations only to preserve or increase safety; absence never implies read-only. Add deterministic case-insensitive patterns for destructive (`delete`, `drop`, `erase`), financial (`purchase`, `payment`, `amount`), credential (`token`, `secret`, `password`), and mutation (`create`, `update`, `write`, `send`, `publish`). Return evidence strings used verbatim in the route card.

- [ ] **Step 5: Run tests**

Run: `pytest tests/test_passport.py tests/test_risk.py -v`  
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add helpers/passport.py helpers/risk.py tests/test_passport.py tests/test_risk.py
git commit -m "feat: enforce capability passports and tool risk classification"
```

### Task 5: Add approval leases and the redacted integrity-chained audit store

**Files:**
- Create: `helpers/storage.py`
- Create: `helpers/leases.py`
- Create: `helpers/audit.py`
- Create: `tests/test_leases.py`
- Create: `tests/test_audit.py`

**Interfaces:**
- Produces: `LeaseStore.issue`, `LeaseStore.consume`, `LeaseStore.revoke_scope`, `AuditStore.append`, `AuditStore.list_redacted`, and `AuditStore.verify_chain`.

- [ ] **Step 1: Write failing replay and redaction tests**

```python
def test_mutation_lease_is_single_use_and_bound_to_hash(store, mutation_request):
    lease = store.issue(mutation_request, ttl_seconds=60, max_uses=1)
    assert store.consume(lease.id, mutation_request).allowed is True
    assert store.consume(lease.id, mutation_request).reason == "lease_exhausted"
    changed = replace(mutation_request, schema_hash="different")
    assert store.consume(lease.id, changed).reason == "lease_binding_mismatch"


def test_audit_redacts_secrets_and_detects_tampering(audit_store):
    audit_store.append(event(arguments={"token": "abc", "query": "safe"}))
    exported = audit_store.list_redacted(limit=10)
    assert "abc" not in json.dumps(exported)
    assert exported[0]["arguments"] == {"token": "[REDACTED]", "query": "safe"}
    audit_store.corrupt_for_test(1)
    assert audit_store.verify_chain().valid is False
```

- [ ] **Step 2: Verify failure**

Run: `pytest tests/test_leases.py tests/test_audit.py -v`  
Expected: FAIL.

- [ ] **Step 3: Implement scoped SQLite storage**

Resolve the database with `plugins.determine_plugin_asset_path("sam_mesh", project, profile, "state.sqlite3")`. Create `leases` and `audit_events` tables with WAL mode, transactional consume (`BEGIN IMMEDIATE`), UTC timestamps, and no raw lease token column. Lease IDs use `secrets.token_urlsafe(32)` and are stored as SHA-256 digests.

- [ ] **Step 4: Implement redaction, chaining, and retention**

Redact keys matching `token|secret|password|authorization|cookie|credential` recursively. Hash each canonical event with the prior chain hash. Retain 30 days or 10,000 events per scope. Export only the redacted representation.

- [ ] **Step 5: Run storage tests**

Run: `pytest tests/test_leases.py tests/test_audit.py -v`  
Expected: PASS including concurrent consume and tamper detection.

- [ ] **Step 6: Commit**

```bash
git add helpers/storage.py helpers/leases.py helpers/audit.py tests/test_leases.py tests/test_audit.py
git commit -m "feat: add single-use leases and integrity-chained audit"
```

### Task 6: Implement the Delegation Gate and native Agent Zero tools

**Files:**
- Create: `helpers/gate.py`
- Create: `tools/sam_mesh_status.py`
- Create: `tools/sam_list_local_services.py`
- Create: `tools/sam_discover_services.py`
- Create: `tools/sam_find_tools.py`
- Create: `tools/sam_describe_tool.py`
- Create: `tools/sam_preflight_tool.py`
- Create: `tools/sam_call_remote_tool.py`
- Create: `tools/sam_list_models.py`
- Create: `tools/sam_route_preview.py`
- Create: `prompts/agent.system.tool.sam_mesh_status.md`
- Create: `prompts/agent.system.tool.sam_list_local_services.md`
- Create: `prompts/agent.system.tool.sam_discover_services.md`
- Create: `prompts/agent.system.tool.sam_find_tools.md`
- Create: `prompts/agent.system.tool.sam_describe_tool.md`
- Create: `prompts/agent.system.tool.sam_preflight_tool.md`
- Create: `prompts/agent.system.tool.sam_call_remote_tool.md`
- Create: `prompts/agent.system.tool.sam_list_models.md`
- Create: `prompts/agent.system.tool.sam_route_preview.md`
- Create: `tests/test_gate.py`
- Create: `tests/test_tools.py`

**Interfaces:**
- Consumes: client, passport evaluator, risk classifier, lease store, audit store.
- Produces: `DelegationGate.preflight(...) -> PreflightDecision`, `DelegationGate.invoke(...) -> ToolResult`, and nine Agent Zero tool entry points.

- [ ] **Step 1: Write failing gate tests**

```python
@pytest.mark.asyncio
async def test_gate_blocks_call_without_required_lease(gate, mutation_descriptor):
    decision = await gate.preflight(mutation_descriptor, {"record": "x"}, DataClass.INTERNAL)
    assert decision.outcome == "needs_approval"
    result = await gate.invoke(decision.id)
    assert result.error_code == "approval_required"


@pytest.mark.asyncio
async def test_gate_never_retries_mutation(gate, approved_mutation, sam_client):
    sam_client.fail_after_remote_success = True
    result = await gate.invoke(approved_mutation.id)
    assert result.error_code == "duplicate_execution_possible"
    assert sam_client.call_count == 1
```

- [ ] **Step 2: Verify failure**

Run: `pytest tests/test_gate.py tests/test_tools.py -v`  
Expected: FAIL.

- [ ] **Step 3: Implement preflight and invocation**

Persist preflight decisions for five minutes. Re-resolve descriptor, passport hash, route, and lease immediately before invocation. Call `describe_remote_tool` before first use or after cache expiry. Pass `arguments` as an object and required labels as one comma-separated string. Never retry mutation/destructive/financial/credential/unknown calls in plugin code.

- [ ] **Step 4: Implement one exact-schema prompt per tool**

For example, `sam_call_remote_tool` accepts only:

```json
{
  "type": "object",
  "properties": {
    "decision_id": {"type": "string", "minLength": 20}
  },
  "required": ["decision_id"],
  "additionalProperties": false
}
```

Tool files subclass `helpers.tool.Tool`, return `Response(message=<json>, break_loop=False)`, and never accept a raw destination or token in the invoke step.

- [ ] **Step 5: Run gate/tool tests**

Run: `pytest tests/test_gate.py tests/test_tools.py -v`  
Expected: PASS; scan test history fixtures for secret values and find none.

- [ ] **Step 6: Commit**

```bash
git add helpers/gate.py tools prompts tests/test_gate.py tests/test_tools.py
git commit -m "feat: add destination-aware delegation gate and sam tools"
```

### Task 7: Build protected control APIs and Mesh Observatory UI

**Files:**
- Create: `api/status.py`
- Create: `api/catalog.py`
- Create: `api/preflight.py`
- Create: `api/approve.py`
- Create: `api/revoke.py`
- Create: `api/audit.py`
- Create: `api/emergency_disconnect.py`
- Create: `webui/config.html`
- Create: `webui/observatory.html`
- Create: `webui/observatory-store.js`
- Create: `webui/observatory.css`
- Create: `extensions/webui/right-canvas-panels/sam-observatory.html`
- Create: `extensions/webui/right_canvas_register_surfaces/register-sam.js`
- Create: `tests/test_api_security.py`
- Create: `tests/test_observatory_static.py`

**Interfaces:**
- Produces: authenticated/CSRF-protected APIs and right-canvas surface ID `sam-observatory`.

- [ ] **Step 1: Write failing API and static UI tests**

```python
def test_approval_api_requires_auth_and_csrf(client):
    assert client.post("/api/plugins/sam_mesh/approve", json={}).status_code in {401, 403}


def test_observatory_has_required_views(plugin_root):
    text = (plugin_root / "webui/observatory.html").read_text()
    for view in ("Node", "Catalog", "Routes", "Activity", "Embassy"):
        assert f">{view}<" in text
    assert "Verified now" in text
    assert "Partial discovery" in text
    assert "Emergency disconnect" in text
```

- [ ] **Step 2: Verify failure**

Run: `pytest tests/test_api_security.py tests/test_observatory_static.py -v`  
Expected: FAIL because APIs/UI do not exist.

- [ ] **Step 3: Implement protected APIs**

Each handler subclasses `ApiHandler`; do not override `requires_auth` or `requires_csrf`. `approve` accepts a `decision_id`, selected lease scope, and typed acknowledgment; it never accepts destination/arguments independent of the decision. `emergency_disconnect` atomically sets safe feature flags, revokes scope leases, drains plugin-owned activity, and succeeds even when SAM is unreachable.

- [ ] **Step 4: Implement the Observatory surface**

Follow Agent Zero's right-canvas surface registration pattern with ID `sam-observatory`, icon `hub`, order 45, and `modalPath: "/plugins/sam_mesh/webui/observatory.html"`. Use Alpine store state only; escape all remote descriptions/schemas through text binding, never `x-html`. Render explicit fact-state chips and any-of label copy.

- [ ] **Step 5: Run UI/API tests**

Run: `pytest tests/test_api_security.py tests/test_observatory_static.py -v`  
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add api webui extensions/webui tests/test_api_security.py tests/test_observatory_static.py
git commit -m "feat: add mesh observatory and protected approval controls"
```

### Task 8: Add safe native MCP configuration and diagnostics

**Files:**
- Create: `helpers/native_mcp.py`
- Create: `api/native_mcp_plan.py`
- Create: `execute.py`
- Create: `skills/sam-mesh/SKILL.md`
- Create: `README.md`
- Create: `tests/test_native_mcp.py`
- Create: `tests/test_execute.py`

**Interfaces:**
- Produces: `build_native_mcp_plan(config, compatibility) -> McpPlan`; no direct asynchronous `MCPConfig.update()` call.

- [ ] **Step 1: Write the failing safe-list test**

```python
def test_native_mcp_plan_disables_every_non_read_tool(report, http_config):
    plan = build_native_mcp_plan(http_config, report)
    assert plan.transport == "streamable_http"
    assert set(plan.enabled_tools) == {
        "get_mesh_info", "list_local_services", "discover_remote_services",
        "find_remote_tools", "describe_remote_tool", "check_connectivity", "get_token_info",
    }
    assert "call_remote_tool" in plan.disabled_tools
    assert "get_recent_logs" in plan.disabled_tools
```

- [ ] **Step 2: Verify failure**

Run: `pytest tests/test_native_mcp.py tests/test_execute.py -v`  
Expected: FAIL.

- [ ] **Step 3: Implement plan-only MCP setup**

The API returns an exact proposed Agent Zero MCP entry for user review and the supported Apply endpoint. It refuses UDS because Agent Zero's native MCP config has no UDS field. Never embed a token retrieved from a token file into the response; require an operator-managed header only in Raw MCP mode and show the credential-exposure warning.

- [ ] **Step 4: Implement idempotent diagnostics**

`execute.py` checks `sam-node --version`, socket existence/mode, configured endpoint reachability, and prints cleanup guidance. It exits nonzero on configuration failure and never runs install, join, reset, or a long-lived daemon.

- [ ] **Step 5: Write versioned operator guidance**

The plugin-local skill teaches canonical `mcp://service/tool` names, Streamable HTTP, any-of labels, automatic versus pinned inference, and describe/preflight before call. README documents Docker addressing and the release compatibility matrix.

- [ ] **Step 6: Run tests and commit**

Run: `pytest tests/test_native_mcp.py tests/test_execute.py -v`  
Expected: PASS.

```bash
git add helpers/native_mcp.py api/native_mcp_plan.py execute.py skills README.md tests/test_native_mcp.py tests/test_execute.py
git commit -m "feat: add safe native mcp setup and operator diagnostics"
```

### Task 9: Run integration, adversarial, and release gates

**Files:**
- Create: `tests/integration/test_agent_zero_plugin.py`
- Create: `tests/integration/test_sam_alpha7.py`
- Create: `tests/integration/test_sam_main.py`
- Create: `tests/adversarial/test_prompt_injection.py`
- Create: `tests/adversarial/test_ssrf.py`
- Create: `tests/adversarial/test_secret_leakage.py`
- Create: `tests/performance/test_control_plane_latency.py`
- Create: `scripts/compatibility-report.py`
- Create: `docs/compatibility.md`

**Interfaces:**
- Produces: machine-readable `compatibility.json` and human-readable compatibility table.

- [ ] **Step 1: Add failing end-to-end assertions**

Assert plugin discovery, scoped config, exact tool identities, read-only MCP safe list, schema-change lease invalidation, mutation no-retry, emergency disconnect, and no secret occurrence across config API responses/log/history/audit export.

Add a deterministic local performance test that runs 200 cached preflights, computes `statistics.quantiles(samples, n=100)[94]`, and requires P95 below `0.150` seconds. Against a healthy fake local node, require Observatory status refresh below `2.0` seconds. With SAM offline, require emergency local lease revocation and feature disablement below `0.500` seconds.

- [ ] **Step 2: Run against the fake sidecar first**

Run: `pytest tests/integration tests/adversarial -v`  
Expected: FAIL until fixtures and all gates are wired.

- [ ] **Step 3: Add SAM release containers and capability report**

Start `v0.1.0-alpha.7` and audited/current-main node fixtures separately. Do not assert unsupported features are present; assert they are labeled `missing`/`schema_mismatch` and disabled. The report records commit/tag, tool names, schema hashes, and endpoint probes.

- [ ] **Step 4: Run the full release suite**

Run: `pytest -v && ruff check . && python scripts/compatibility-report.py --verify docs/compatibility.md`  
Expected: all tests pass, Ruff clean, generated compatibility data matches the checked-in table.

- [ ] **Step 5: Perform the secret scan**

Run: `rg -n "test-node-secret|Authorization: Bearer test|X-Sam-Authentication: Bearer test" .pytest_cache test-output logs exports`  
Expected: no matches.

- [ ] **Step 6: Commit**

```bash
git add tests scripts/compatibility-report.py docs/compatibility.md
git commit -m "test: certify core plugin across agent zero and sam tracks"
```

## Core release gate

Core `1.0.0` can ship when Tasks 1–9 pass, the compatibility report names every disabled SAM capability, zero secrets appear in scans, every mutation path requires a single-use lease, and emergency disconnect works with the SAM node offline.

## Current execution assessment

The 2026-09-10 task and release-gate assessment is in [release-readiness](../../release-readiness.md). Historical step checkboxes remain unclaimed where live certification or the planned commit boundary has not occurred. Implementation adaptations and exact source revisions are recorded in [compatibility](../../compatibility.md).
