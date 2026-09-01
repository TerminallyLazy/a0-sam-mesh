# A0 SAM Cognitive Relay Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make SAM mesh inference a native Agent Zero chat provider with visibly distinct resilient and named-destination routes.

**Architecture:** The plugin contributes a `sam_mesh` provider to Agent Zero's existing model-provider catalog. Normal A0 model presets carry API base and route headers, while plugin APIs provide compatibility probes, route previews, and destination-aware approval for pinned sensitive routes.

**Tech Stack:** Agent Zero provider merge and Model Config plugin, LiteLLM OpenAI chat mode, SAM `/v1/models` and `/v1/chat/completions`, httpx, Alpine.js, pytest.

**Spec:** `docs/superpowers/specs/2026-08-31-a0-sam-mesh-embassy-design.md`

## Global Constraints

- Provider ID is exactly `sam_mesh`; it uses OpenAI chat mode, not Responses mode.
- Native provider mode requires an HTTP-reachable SAM facade; plugin-owned UDS remains available for discovery and guarded tools.
- The node token is stored once in Agent Zero's masked `sam_mesh` provider credential and sent through the `/v1` Authorization compatibility path.
- Sovereign mode uses `http://mesh.sam.alt/v1` and no agent-held SAM token.
- Automatic routing is never described as exact recipient disclosure.
- Named routing appends `/v1` to the discovered service proxy root and revalidates destination before sensitive transmission.
- `X-Sam-Required-Labels` is one comma-separated any-of header.
- Support only models, chat completions, and legacy completions exposed by SAM; do not claim embeddings, Responses, images, audio, or batches.
- Feature support is runtime-probed against SAM `v0.1.0-alpha.7` and audited/current main.

---

## File map

| Path | Responsibility |
|---|---|
| `conf/model_providers.yaml` | Agent Zero provider registration |
| `helpers/inference.py` | Route normalization, preset fragments, compatibility checks |
| `api/inference_probe.py` | Streaming/non-streaming/tool-call contract probe |
| `api/inference_routes.py` | Route list and destination preview |
| `api/inference_profile.py` | Validated model-preset fragment generation |
| `webui/inference-routes.html` | Resilient versus Named Sovereign UX |
| `tests/test_provider.py` | Provider merge and credential behavior |
| `tests/contract/test_inference.py` | SAM facade contract matrix |

### Task 1: Register the SAM provider in Agent Zero

**Files:**
- Create: `conf/model_providers.yaml`
- Create: `tests/test_provider.py`
- Modify: `README.md`

**Interfaces:**
- Produces: provider ID `sam_mesh` visible to Agent Zero's chat-provider catalog.

- [ ] **Step 1: Write the failing provider-merge test**

```python
def test_enabled_plugin_registers_sam_chat_provider(a0_checkout, installed_plugin):
    from helpers.providers import ProviderManager
    ProviderManager.reload()
    cfg = ProviderManager.get_instance().get_provider_config("chat", "sam_mesh")
    assert cfg["name"] == "SAM Mesh"
    assert cfg["litellm_provider"] == "openai"
    assert cfg["api_key_mode"] == "optional"
    assert cfg["models_list"]["endpoint_url"] == "/models"
    assert cfg["kwargs"]["a0_api_mode"] == "chat"
```

- [ ] **Step 2: Verify failure**

Run: `pytest tests/test_provider.py::test_enabled_plugin_registers_sam_chat_provider -v`  
Expected: FAIL because `conf/model_providers.yaml` is absent.

- [ ] **Step 3: Create the provider definition**

```yaml
chat:
  sam_mesh:
    name: SAM Mesh
    litellm_provider: openai
    api_key_mode: optional
    models_list:
      endpoint_url: /models
      format: openai
      default_base: http://127.0.0.1:8080/v1
    kwargs:
      a0_api_mode: chat
```

Do not put a token, static labels, or one deployment-specific API base in provider defaults.

- [ ] **Step 4: Verify provider visibility and disabled-plugin removal**

Run: `pytest tests/test_provider.py -v`  
Expected: PASS when enabled; a second test confirms `sam_mesh` disappears after plugin disable and provider reload.

- [ ] **Step 5: Commit**

```bash
git add conf/model_providers.yaml tests/test_provider.py README.md
git commit -m "feat: register sam mesh as an agent zero model provider"
```

### Task 2: Implement validated resilient and pinned route profiles

**Files:**
- Create: `helpers/inference.py`
- Create: `tests/test_inference_routes.py`

**Interfaces:**
- Consumes: `ResolvedConfig`, discovered `MeshModel`, `CapabilityPassport`.
- Produces: `InferenceRoute`, `build_preset_fragment(route) -> dict`, `validate_inference_route(route, passport)`.

- [ ] **Step 1: Write failing route tests**

```python
def test_resilient_route_serializes_any_of_labels():
    route = InferenceRoute.automatic(
        base_url="http://sam-node:8080/v1",
        model="research-model",
        required_labels=("region=us", "phi=false"),
    )
    fragment = build_preset_fragment(route)
    assert fragment["provider"] == "sam_mesh"
    assert fragment["api_base"] == "http://sam-node:8080/v1"
    assert fragment["kwargs"]["extra_headers"] == {
        "X-Sam-Required-Labels": "region=us,phi=false"
    }


def test_pinned_route_requires_exact_peer_and_proxy_root(passport):
    route = InferenceRoute.pinned(peer_id="", service="reviewer", proxy_root="http://x")
    with pytest.raises(RouteValidationError, match="peer_id"):
        validate_inference_route(route, passport)
```

- [ ] **Step 2: Verify failure**

Run: `pytest tests/test_inference_routes.py -v`  
Expected: FAIL.

- [ ] **Step 3: Implement route normalization**

For automatic routes, require an API base ending in `/v1`. For pinned routes, accept only a proxy root returned by the current discovery cache, bind it to peer/service/catalog timestamp, and derive `api_base = proxy_root.rstrip("/") + "/v1"`. Reject userinfo, fragments, redirects, and hosts not matching the configured SAM sidecar.

- [ ] **Step 4: Build Agent Zero model-preset fragments**

Return only `provider`, `name`, `api_base`, context/rate fields selected by the operator, and known-safe kwargs. Never copy arbitrary HTTP headers from discovery. Set `extra_headers` only from validated required labels.

- [ ] **Step 5: Run tests and commit**

Run: `pytest tests/test_inference_routes.py -v`  
Expected: PASS.

```bash
git add helpers/inference.py tests/test_inference_routes.py
git commit -m "feat: add resilient and pinned mesh inference routes"
```

### Task 3: Add inference compatibility probes and error taxonomy

**Files:**
- Create: `api/inference_probe.py`
- Create: `tests/contract/test_inference.py`
- Modify: `helpers/domain.py`
- Modify: `helpers/sam_client.py`

**Interfaces:**
- Produces: `InferenceCompatibilityReport` with model-list, non-streaming, streaming, tool-call, auth, not-found, and exhaustion results.

- [ ] **Step 1: Write the failing contract matrix**

```python
@pytest.mark.parametrize("stream", [False, True])
@pytest.mark.asyncio
async def test_chat_completion_contract(fake_inference_sidecar, sam_client, stream):
    result = await sam_client.probe_chat(model="probe-model", stream=stream)
    assert result.content == "probe-ok"
    assert result.streamed is stream


@pytest.mark.asyncio
async def test_error_mapping(sam_client, fake_inference_sidecar):
    fake_inference_sidecar.next_status = 404
    assert (await sam_client.probe_chat("missing")).error_code == "model_not_found"
    fake_inference_sidecar.next_status = 503
    assert (await sam_client.probe_chat("busy")).error_code == "provider_exhausted"
```

- [ ] **Step 2: Verify failure**

Run: `pytest tests/contract/test_inference.py -v`  
Expected: FAIL.

- [ ] **Step 3: Implement non-destructive probes**

`inference_probe` receives a route ID, uses a fixed `probe` request with `max_tokens=8`, and reports response/stream/tool-call structure without exposing prompt content or credentials. A route is production-capable only when model listing plus the configured streaming mode pass.

- [ ] **Step 4: Map facade failures distinctly**

Map 401/403, 404, 429, 502/503/504, malformed chunks, timeouts, and midstream disconnects into the spec's error codes. Show that automatic SAM routing may have attempted several providers; do not issue an extra A0 SAM retry.

- [ ] **Step 5: Run tests and commit**

Run: `pytest tests/contract/test_inference.py -v`  
Expected: PASS.

```bash
git add api/inference_probe.py helpers/domain.py helpers/sam_client.py tests/contract/test_inference.py
git commit -m "feat: probe and classify sam inference compatibility"
```

### Task 4: Build route preview, profile generation, and sensitive-destination approval

**Files:**
- Create: `api/inference_routes.py`
- Create: `api/inference_profile.py`
- Create: `api/inference_approve.py`
- Create: `webui/inference-routes.html`
- Modify: `webui/observatory-store.js`
- Modify: `webui/observatory.html`
- Create: `tests/test_inference_api.py`
- Create: `tests/test_inference_ui.py`

**Interfaces:**
- Produces: route cards, validated A0 preset fragments, and a named-destination lease bound to peer/service/model/data class.

- [ ] **Step 1: Write failing UX/security tests**

```python
def test_automatic_route_copy_never_promises_exact_recipient(plugin_root):
    text = (plugin_root / "webui/inference-routes.html").read_text()
    assert "SAM may select or fail over between eligible providers" in text
    assert "Exact recipient guaranteed" not in text


def test_sensitive_pinned_approval_binds_destination(api_client, discovered_route):
    decision = api_client.post_json("inference_profile", discovered_route).json()
    lease = api_client.post_json("inference_approve", {
        "decision_id": decision["decision_id"], "acknowledge_recipient": True
    }).json()
    assert lease["peer_id"] == discovered_route["peer_id"]
    assert lease["max_uses"] == 1
```

- [ ] **Step 2: Verify failure**

Run: `pytest tests/test_inference_api.py tests/test_inference_ui.py -v`  
Expected: FAIL.

- [ ] **Step 3: Implement Routes UI**

Show two large route cards: `Resilient Mesh` and `Named Sovereign`. The resilient card explains local-first/failover and any-of labels. The named card displays peer ID, service, attested labels, discovery age, and recipient approval state. The generated preset fragment is copied through a user action; do not silently overwrite `_model_config` presets.

- [ ] **Step 4: Implement sensitive route leases**

Confidential/regulated pinned routes require a lease bound to peer, service, model, schema/catalog hash, data class, and a single first transmission. A catalog refresh that changes peer/service invalidates it.

- [ ] **Step 5: Run tests and commit**

Run: `pytest tests/test_inference_api.py tests/test_inference_ui.py -v`  
Expected: PASS.

```bash
git add api/inference_routes.py api/inference_profile.py api/inference_approve.py webui tests/test_inference_api.py tests/test_inference_ui.py
git commit -m "feat: add mesh inference route controls and recipient approval"
```

### Task 5: Certify native Agent Zero model operation across supported SAM tracks

**Files:**
- Create: `tests/integration/test_a0_sam_model.py`
- Create: `tests/integration/test_sam_inference_matrix.py`
- Create: `docs/cognitive-relay.md`
- Modify: `docs/compatibility.md`

**Interfaces:**
- Produces: a checked compatibility table for model listing, streaming, tool calls, automatic routing, pinned routing, and sovereign no-token mode.

- [ ] **Step 1: Add end-to-end model tests**

Install the plugin in Agent Zero, reload providers, construct a `sam_mesh` `ModelConfig`, and execute both `get_chat_model(...).ainvoke` and streaming generation against the SAM fixture. Assert A0 tool-call JSON survives the SAM/OpenAI facade and no node token appears in exception/log output.

- [ ] **Step 2: Run the matrix against alpha.7 and current main**

Run: `pytest tests/integration/test_a0_sam_model.py tests/integration/test_sam_inference_matrix.py -v`  
Expected: supported cells pass; unsupported cells are explicitly skipped from probe output with a capability reason, never assumed.

- [ ] **Step 3: Test sovereign provider configuration**

Set API base `http://mesh.sam.alt/v1`, provider credential `NA`, and assert the fake `sam-box` route receives no Authorization header containing a node token.

- [ ] **Step 4: Update the compatibility document**

Document exact tested tag/SHA and results for models, non-streaming, streaming, tool calls, labels, automatic failover, pinned proxy, and midstream failure.

- [ ] **Step 5: Commit**

```bash
git add tests/integration docs/cognitive-relay.md docs/compatibility.md
git commit -m "test: certify cognitive relay across sam release tracks"
```

## Cognitive Relay release gate

Release as beta only when native Agent Zero chat and utility slots pass streaming and tool-call tests, automatic routing copy is truthful, named routes bind exact destination leases, and no provider/node credential appears in browser responses, chat history, logs, or exported diagnostics.
