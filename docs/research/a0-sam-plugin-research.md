# A0 SAM Plugin — Research Dossier and Concept Direction

**Status:** research and concept direction; not yet an approved design or implementation plan  
**Audit date:** 2026-08-31  
**Agent Zero snapshot:** [`6a6cecff`](https://github.com/agent0ai/agent-zero/commit/6a6cecff8527b164668c7a6ab2f76b6b1ed7cfa1) (2026-08-27)  
**SAM snapshot:** [`3224aae8`](https://github.com/google/sam/commit/3224aae8dc962d6e8d4a83c4fa1f2d3e84c6db0f) (2026-08-29)  
**Latest published SAM release at audit time:** [`v0.1.0-alpha.7`](https://github.com/google/sam/releases/tag/v0.1.0-alpha.7) (2026-08-16)

## Executive verdict

The preliminary brief found the right seam—Agent Zero and SAM meet naturally at MCP and OpenAI-compatible inference—but it stops one layer too early. A thin “bootstrap plus chat-completion tool” would work, yet it would fail to exploit Agent Zero as a model host, fail to make Agent Zero useful *to* the mesh, and give a generic remote-call tool more authority than Agent Zero’s policy engine can safely understand.

The strongest product is a **Mesh Embassy** with four separable planes:

1. **Capability plane:** discover and use SAM services as typed Agent Zero capabilities.
2. **Cognition plane:** make SAM inference a native Agent Zero model provider, not a nested “ask another model” tool.
3. **Embassy plane:** publish selected Agent Zero agents/projects back into SAM as deliberately bounded services.
4. **Sovereign boundary:** optionally run Agent Zero behind `sam-box`, so SAM policy governs network egress at the sandbox boundary rather than relying only on model obedience.

The recommended v1 distribution is a **community plugin plus an optional companion deployment pack**. The plugin should work with ordinary Agent Zero installations; the companion pack should add the stronger `sam-box` boundary only where the installed SAM build actually supports it.

The central architectural correction is this: **use a guarded, plugin-owned client as the safe default for SAM discovery and invocation, while offering Agent Zero’s native MCP registration as an expert/read-only fast lane.** Native MCP is valuable, but direct access to SAM’s generic `call_remote_tool` collapses every downstream peer/service/tool into one policy identity, `mcp:sam_mesh:call_remote_tool`. Agent Zero can allow or block that gateway, but it cannot express policy over the gateway’s runtime destination arguments. [Agent Zero tool policy](https://github.com/agent0ai/agent-zero/blob/6a6cecff8527b164668c7a6ab2f76b6b1ed7cfa1/helpers/tool_policy.py#L141-L208) [SAM MCP implementation](https://github.com/google/sam/blob/3224aae8dc962d6e8d4a83c4fa1f2d3e84c6db0f/internal/node/mcp.go)

## What Agent Zero actually offers

Agent Zero is more than a tool runner. Its current README describes a containerized agent workspace with a Linux desktop, browser control, projects, skills, plugins, multi-agent delegation, MCP/A2A integration, project-scoped configuration, model presets, and a host bridge. [Agent Zero README](https://github.com/agent0ai/agent-zero/blob/6a6cecff8527b164668c7a6ab2f76b6b1ed7cfa1/README.md)

The plugin system is unusually broad. An enabled plugin can own tools, prompts, helpers, APIs, WebUI extensions, agent profiles, skills, and even model-provider definitions. User plugins are discovered under `usr/plugins/<name>` when `plugin.yaml` is present; community plugins are distributed as standalone repositories whose runtime files live at repository root. [Plugin discovery](https://github.com/agent0ai/agent-zero/blob/6a6cecff8527b164668c7a6ab2f76b6b1ed7cfa1/helpers/plugins.py#L225-L262) [Plugin contract](https://github.com/agent0ai/agent-zero/blob/6a6cecff8527b164668c7a6ab2f76b6b1ed7cfa1/plugins/AGENTS.md#L5-L33) [Community-plugin workflow](https://github.com/agent0ai/agent-zero/blob/6a6cecff8527b164668c7a6ab2f76b6b1ed7cfa1/skills/a0-create-plugin/SKILL.md#L14-L28)

### High-value seams

| Agent Zero seam | Verified behavior | A0 SAM implication |
|---|---|---|
| Native tools | A tool is resolved from an exact `tools/<name>.py` file and receives its own `plugin:<plugin>:<tool>` policy identity. [Dispatch](https://github.com/agent0ai/agent-zero/blob/6a6cecff8527b164668c7a6ab2f76b6b1ed7cfa1/agent.py#L1562-L1596) [Policy identities](https://github.com/agent0ai/agent-zero/blob/6a6cecff8527b164668c7a6ab2f76b6b1ed7cfa1/helpers/tool_policy.py#L253-L329) | Separate read-only discovery from remote execution, peer connection, pubsub, logs, and inference instead of granting one broad gateway. |
| MCP client | Remote MCP supports Streamable HTTP and SSE, headers, timeouts, disabled tools, project scope, prompt/schema generation, media results, and policy enforcement at execution. It has no Unix-socket field. [MCP models/transports](https://github.com/agent0ai/agent-zero/blob/6a6cecff8527b164668c7a6ab2f76b6b1ed7cfa1/helpers/mcp_handler.py#L533-L738) [Remote transports](https://github.com/agent0ai/agent-zero/blob/6a6cecff8527b164668c7a6ab2f76b6b1ed7cfa1/helpers/mcp_handler.py#L1606-L1666) | Offer direct MCP for HTTP-reachable nodes, especially read-oriented tools; use a plugin client for UDS, per-profile policy, and guarded invocation. |
| MCP server | Agent Zero can expose chats through an MCP server with `send_message` and `finish_chat`, including persistent chat IDs and project paths. [A0 MCP server](https://github.com/agent0ai/agent-zero/blob/6a6cecff8527b164668c7a6ab2f76b6b1ed7cfa1/helpers/mcp_server.py) | This can become the seed of the “Embassy” inbound service, but a plugin broker is needed for explicit profile/project allowlists and stronger inbound limits. |
| Model providers | Enabled plugins may merge `conf/model_providers.yaml` after the base catalog. Provider definitions can select LiteLLM’s OpenAI provider, an API base, headers, and model-list endpoint. [Provider merge](https://github.com/agent0ai/agent-zero/blob/6a6cecff8527b164668c7a6ab2f76b6b1ed7cfa1/helpers/providers.py#L64-L84) [Provider schema](https://github.com/agent0ai/agent-zero/blob/6a6cecff8527b164668c7a6ab2f76b6b1ed7cfa1/conf/model_providers.yaml#L1-L26) | Register SAM’s OpenAI-compatible facade as a real chat provider so an A0 agent can *be powered by* a mesh model. |
| Scoped config | Plugin config and activation can be project/profile scoped, but MCP configuration is global/project scoped rather than profile scoped. [Plugin precedence](https://github.com/agent0ai/agent-zero/blob/6a6cecff8527b164668c7a6ab2f76b6b1ed7cfa1/helpers/plugins.py#L766-L829) [MCP cache/scope](https://github.com/agent0ai/agent-zero/blob/6a6cecff8527b164668c7a6ab2f76b6b1ed7cfa1/helpers/mcp_handler.py#L807-L882) | A plugin-owned client can implement per-profile “capability passports”; direct MCP alone cannot. |
| Skills | Enabled plugin skills are first-class catalog roots and survive context compaction through Agent Zero’s skill recall/reattachment flow. [Skill roots](https://github.com/agent0ai/agent-zero/blob/6a6cecff8527b164668c7a6ab2f76b6b1ed7cfa1/helpers/skills.py#L70-L99) [Plugin skill catalog](https://github.com/agent0ai/agent-zero/blob/6a6cecff8527b164668c7a6ab2f76b6b1ed7cfa1/helpers/skills.py#L1372-L1401) | Ship SAM operating guidance inside the plugin, versioned with the adapter it describes. |
| Protected UI/API | Plugin APIs default to authenticated, CSRF-protected POST; plugin assets and extension points can build custom setup/consent experiences. [API guards](https://github.com/agent0ai/agent-zero/blob/6a6cecff8527b164668c7a6ab2f76b6b1ed7cfa1/helpers/api.py#L33-L59) [Plugin asset routes](https://github.com/agent0ai/agent-zero/blob/6a6cecff8527b164668c7a6ab2f76b6b1ed7cfa1/helpers/ui_server.py#L402-L449) | Put install/join, destination disclosure, and risky-call approval in protected UI—not in a model-supplied `confirm=true` argument. |

### Corrections to the preliminary Agent Zero assumptions

- Plugin-owned guidance should live at `skills/sam-mesh/SKILL.md` inside the plugin, not necessarily in top-level `usr/skills`. [Placement guidance](https://github.com/agent0ai/agent-zero/blob/6a6cecff8527b164668c7a6ab2f76b6b1ed7cfa1/skills/build-skill/SKILL.md#L35-L49)
- Native tool prompts live directly under `prompts/agent.system.tool.<name>.md`; prompt discovery is non-recursive, so `prompts/default/...` would be missed. [Prompt assembly](https://github.com/agent0ai/agent-zero/blob/6a6cecff8527b164668c7a6ab2f76b6b1ed7cfa1/extensions/python/system_prompt/_11_tools_prompt.py#L27-L51)
- MCP settings can be applied/refreshed immediately; a session restart is no longer the general rule. [Apply endpoint](https://github.com/agent0ai/agent-zero/blob/6a6cecff8527b164668c7a6ab2f76b6b1ed7cfa1/api/mcp_servers_apply.py#L11-L28)
- `Response(..., break_loop=False)` does not pause for user approval, and a model-supplied `confirm=true` is not a trustworthy authorization primitive. [Execution semantics](https://github.com/agent0ai/agent-zero/blob/6a6cecff8527b164668c7a6ab2f76b6b1ed7cfa1/agent.py#L1198-L1236)
- Stored plugin `config.json` can be returned verbatim to the settings UI, and MCP header values are not among Agent Zero’s masked fields. Raw SAM tokens should therefore not be duplicated in those stores. Prefer UDS where possible; otherwise resolve one secret/token source backend-side. [Plugin settings read](https://github.com/agent0ai/agent-zero/blob/6a6cecff8527b164668c7a6ab2f76b6b1ed7cfa1/api/plugins.py#L55-L91) [Settings masking](https://github.com/agent0ai/agent-zero/blob/6a6cecff8527b164668c7a6ab2f76b6b1ed7cfa1/helpers/settings.py#L310-L347)
- `127.0.0.1` from inside Agent Zero’s Docker container refers to that container. A host or sibling `sam-node` needs a Docker-reachable address or a mounted UDS. [Docker MCP addressing](https://github.com/agent0ai/agent-zero/blob/6a6cecff8527b164668c7a6ab2f76b6b1ed7cfa1/docs/developer/mcp-configuration.md#L53-L66)

## What SAM actually offers

SAM is a closed-by-default, peer-to-peer service mesh for agents. The control plane maps identity claims to policy and signs Biscuit credentials; routers assist discovery/relay; nodes own peer identity, local service registration, the libp2p data plane, and local MCP/OpenAI-compatible facades. A node joins no mesh and exposes no services by default. [SAM overview](https://sam-mesh.dev/docs/) [Policy reference](https://sam-mesh.dev/docs/development/policy/) [Node configuration](https://sam-mesh.dev/docs/user/node-configuration/)

### Local transport and API

- The normal local MCP endpoint is `http://127.0.0.1:8080/mcp` using **MCP Streamable HTTP**. Current sandbox guidance says the older SSE transport receives HTTP 400. [Agent usage](https://sam-mesh.dev/docs/user/agent-usage/) [Running agents](https://sam-mesh.dev/docs/user/running-agents/)
- The same HTTP sidecar may be served over `~/.config/sam-mesh/sam.sock`. That is HTTP over a Unix-domain socket, not a documented raw JSON-RPC socket protocol. The socket is filesystem-protected and does not require the TCP API token. [Sidecar implementation](https://github.com/google/sam/blob/3224aae8dc962d6e8d4a83c4fa1f2d3e84c6db0f/internal/node/sidecar.go)
- TCP authentication normally uses `X-Sam-Authentication: Bearer …`. Selected non-forwarding endpoints, including `/v1/*` and `/mcp`, accept `Authorization` as a compatibility alias; `Authorization` remains reserved for backend credentials on the raw peer proxy. [Agent usage](https://sam-mesh.dev/docs/user/agent-usage/) [Sidecar routes/auth](https://github.com/google/sam/blob/3224aae8dc962d6e8d4a83c4fa1f2d3e84c6db0f/internal/node/sidecar.go)
- The supported inference facade is deliberately small: `GET /v1/models`, `POST /v1/chat/completions`, and `POST /v1/completions`. It is not the full OpenAI API. [OpenAI facade](https://github.com/google/sam/blob/3224aae8dc962d6e8d4a83c4fa1f2d3e84c6db0f/internal/node/openai_facade.go)

### The MCP surface is broader—and riskier—than the brief suggests

Current `main` registers 15 authenticated MCP tools: `send_message`, `list_local_services`, `discover_remote_services`, `mesh_pubsub_broadcast`, `poll_messages`, `subscribe_topic`, `get_mesh_info`, `call_remote_tool`, `connect_peer`, `find_remote_tools`, `describe_remote_tool`, `check_connectivity`, `get_token_info`, `get_network_info`, and `get_recent_logs`. [MCP registration](https://github.com/google/sam/blob/3224aae8dc962d6e8d4a83c4fa1f2d3e84c6db0f/internal/node/mcp.go)

That breadth changes the design:

- Read-oriented discovery can reasonably be enabled by default; peer connection, pubsub, recent logs, and generic remote execution should not be.
- `send_message` is currently simulated and must not be marketed as real peer messaging. [MCP handlers](https://github.com/google/sam/blob/3224aae8dc962d6e8d4a83c4fa1f2d3e84c6db0f/internal/node/mcp_handlers.go)
- `find_remote_tools.intent` is accepted but ignored; this is exact tool-name/catalog search, not semantic discovery. [MCP handlers](https://github.com/google/sam/blob/3224aae8dc962d6e8d4a83c4fa1f2d3e84c6db0f/internal/node/mcp_handlers.go)
- Remote tool names are `mcp://<service>/<tool>` and the discovered canonical value should be passed through verbatim. [SAM skill](https://github.com/google/sam/blob/3224aae8dc962d6e8d4a83c4fa1f2d3e84c6db0f/agents/skills/sam-mesh/SKILL.md)
- `required_labels` is a comma-separated string of exact `key=value` alternatives with **any-of**, not all-of, semantics. [Node labels](https://sam-mesh.dev/docs/user/node-configuration/)
- `call_remote_tool` retries ordinary transport failures up to three times. A reply lost after successful remote execution can therefore duplicate a side effect. Remote mutations require idempotency keys where supported, a duplicate-risk warning, or explicit approval. [SAM call/retry code](https://github.com/google/sam/blob/3224aae8dc962d6e8d4a83c4fa1f2d3e84c6db0f/internal/node/mcp.go)
- SAM’s MCP registrations do not currently attach standard read-only/destructive/idempotent annotations, so the client must maintain a conservative local risk classification. [SAM MCP registration](https://github.com/google/sam/blob/3224aae8dc962d6e8d4a83c4fa1f2d3e84c6db0f/internal/node/mcp.go)

### Inference behavior matters to privacy UX

SAM’s automatic facade is local-first and may try up to three providers, failing over only on selected transient statuses. `/v1/models` is a current aggregate view, not a promise that the same peer will receive the next request. `X-Sam-Required-Labels` narrows candidates, and the selected provider’s signed identity is verified before request bytes leave the node. [Facade routing](https://github.com/google/sam/blob/3224aae8dc962d6e8d4a83c4fa1f2d3e84c6db0f/internal/node/openai_facade.go) [Provider scoring](https://github.com/google/sam/blob/3224aae8dc962d6e8d4a83c4fa1f2d3e84c6db0f/internal/node/openai_scorer.go)

That calls for two explicit inference experiences:

1. **Resilient route:** automatic local-first routing/failover, with destination expressed as a trust/label class rather than a named peer.
2. **Disclosed route:** pin the peer/service through its `local_proxy_url`, append `/v1/chat/completions`, show the exact destination, and obtain approval for sensitive data.

The second mode is not a luxury. It is the only honest way to promise the user that a particular peer will receive a sensitive prompt. [Agent usage](https://sam-mesh.dev/docs/user/agent-usage/) [SAM skill](https://github.com/google/sam/blob/3224aae8dc962d6e8d4a83c4fa1f2d3e84c6db0f/agents/skills/sam-mesh/SKILL.md)

## Release reality: design for capability skew

SAM’s public docs track current development closely, but the newest published release at audit time is `v0.1.0-alpha.7`; current `main` is [roughly 191 commits ahead](https://github.com/google/sam/compare/v0.1.0-alpha.7...main) and includes substantial agent-sandbox, protocol, and security work. The MCP server’s own implementation version is not sufficient to distinguish those capabilities, so the plugin should probe `initialize`, `tools/list`, exact input schemas, health/readiness, and optional endpoints rather than rely on a version string. [Release tracks](https://sam-mesh.dev/docs/development/release-tracks/) [SAM releases](https://github.com/google/sam/releases)

Current documentation and source also disagree in places:

- Docs still mention `a2a`, but the current parser/protobuf accepts `mcp` and `inference`; A0 SAM should not claim A2A until source support returns. [Node configuration](https://sam-mesh.dev/docs/user/node-configuration/) [Service type source](https://github.com/google/sam/blob/3224aae8dc962d6e8d4a83c4fa1f2d3e84c6db0f/api/network.go)
- Some integration pages call the endpoint SSE, while current agent guidance says Streamable HTTP. A0 SAM should use direct Streamable HTTP.
- Some examples use stale tool-name or completion-path forms. The adapter should use discovered canonical tool URIs verbatim and append `/v1/chat/completions` to a pinned service proxy root.

The `sam-box` agent-identity/sandbox architecture is especially promising but belongs behind an experimental capability gate until the targeted released track contains the required attach/status/refresh and gateway behaviors. [Agent architecture](https://sam-mesh.dev/docs/agent-architecture/) [Secure gateway](https://sam-mesh.dev/docs/user/secure-gateway/)

## Assessment of the attached brief

| Preliminary idea | Keep | Upgrade or correct |
|---|---|---|
| Community plugin under `usr/plugins/sam_mesh` | Yes | For Plugin Index distribution, the standalone repository itself should have `plugin.yaml`, `README.md`, and `LICENSE` at its root. |
| Let Agent Zero consume SAM’s native MCP surface | Yes, as a mode | Make it an optional/read-only fast lane, not the universal path. Block the broad `call_remote_tool` unless the user explicitly chooses raw mode. |
| Separate inference from MCP tools | Yes | Go further: add SAM as a native A0 chat provider. Retain a guarded/pinned inference path for recipient disclosure and sensitive-data consent. |
| Dedicated SAM HTTP/UDS client | Yes | It is HTTP over UDS/TCP; do not invent a bare JSON-RPC socket API. Use it to provide per-profile policy, one secret source, guarded calls, and richer diagnostics. |
| `sam_bootstrap` tool | Reframe | Installation, OIDC join, and daemon lifecycle are user/administrator operations. Put them in protected setup UI or a short, idempotent manual plugin action; never let the model silently join a mesh. |
| One prompt per native tool | Yes | Place prompts directly under `prompts/` and include real JSON schemas for Responses-mode safety. |
| Top-level SAM skill | No | Put the skill inside the plugin so versioned operating guidance travels with the integration. |
| Token in plugin config plus MCP settings | No | Avoid duplicate secret stores. Prefer a mounted UDS, or reference a backend secret/token file. Do not expose tokens in tool args, logs, chat history, or ordinary config UI. |
| No additional gate around MCP remote calls | No | The gateway hides downstream identity and SAM may retry ambiguous writes. Add destination-aware policy and a real UI approval/lease mechanism. |

## Candidate product: **A0 SAM Mesh Embassy**

This is a product thesis for discussion, not a locked specification.

### 1. Capability Passport

Each Agent Zero project/profile receives a readable passport describing:

- which SAM node/identity it uses;
- allowed service and tool URI patterns;
- permitted data classes (`public`, `internal`, `confidential`, `regulated`);
- required provider labels and whether they mean “any match”;
- whether remote calls, pubsub, peer connection, logs, and inference are enabled;
- whether routing is automatic or destination-pinned;
- the current capability-probe result and compatibility tier.

This turns scattered endpoint settings into an explainable contract. It also makes a crucial distinction: per-profile plugin settings are *policy overlays*, not separate SAM cryptographic identities. True per-agent principals require the newer `sam-box` agent-namespace architecture.

### 2. Mesh Observatory

A dedicated panel should show only observable facts, with uncertainty visible:

- node enrollment/readiness and token-expiry status;
- discovered services, peer IDs, labels, schemas, and partial-discovery errors;
- local services currently advertised or withheld because their health probe failed;
- recent calls with redacted destinations, route mode, latency, and outcome;
- denied calls and the policy layer that denied them;
- feature probes showing “supported,” “missing,” or “schema mismatch.”

It should not pretend to provide a global topology map, semantic reputation score, durable message queue, or authoritative health for peers that SAM can only observe best-effort.

### 3. Delegation Gate

Remote execution becomes a three-step protocol:

1. **Discover/describe:** resolve the canonical tool URI and fetch its schema.
2. **Preflight:** compare destination, schema, data class, duplicate-execution risk, and passport rules; render a compact route card.
3. **Invoke:** use a short-lived approval lease for the exact peer/service/tool and argument fingerprint when human consent is required.

Direct generic `call_remote_tool` stays blocked in safe mode. Advanced users can enable raw MCP mode, but the UI should explain that this grants a broad gateway rather than one downstream tool.

### 4. Cognitive Relay

The plugin contributes a SAM chat provider through `conf/model_providers.yaml`, allowing SAM-backed models to fill Agent Zero’s chat/utility/browser model slots and presets. That avoids nested-agent semantics and keeps Agent Zero’s normal context, tool loop, token accounting, and model configuration intact.

Two route profiles sit above the provider:

- **Resilient Mesh:** local-first and failover-capable, filtered by policy labels.
- **Named Sovereign:** peer/service pinned, recipient shown before sensitive content leaves.

The native provider path should be treated as an integration spike until streaming, tool-call payloads, model-list refresh, auth aliasing, labels, and errors have been verified against the supported SAM track.

### 5. Embassy Publisher

Agent Zero should not only consume the mesh. A later milestone can publish carefully selected A0 capabilities through a local MCP backend registered in `sam-node.yaml`:

- a stateless “ask this bounded specialist” service;
- an allowlisted persistent project chat;
- a research/development team endpoint with strict attachment and duration limits;
- curated local tools exposed individually, never the entire Agent Zero tool surface by default.

Inbound requests need a broker that maps a SAM-verified origin to an allowed A0 project/profile, caps runtime and attachments, rate-limits callers, isolates memory, records origin facts, and treats remote instructions/results as untrusted content. Agent Zero’s built-in MCP server is a useful substrate, not the complete security boundary.

### 6. Sovereign Deployment Pack

For installations that target a sufficiently new SAM build, an optional Compose/launcher profile can put Agent Zero behind one `sam-box` per sandbox and one `sam-node` per host. Agent Zero then runs without general network access; SAM becomes the egress/ingress enforcement point and provider credentials remain outside the agent container. This cannot be retrofitted by Python plugin code alone—it requires container/network/mount configuration. [Agent architecture](https://sam-mesh.dev/docs/agent-architecture/)

## Three development approaches

| Approach | Shape | Advantages | Limits |
|---|---|---|---|
| **A. Hybrid Embassy** — recommended | Community plugin: guarded native client + SAM model provider + optional read-only native MCP; later inbound publisher and companion `sam-box` pack | Best security/product differentiation; per-profile passports; supports UDS; preserves A0-native cognition; graceful path to sovereign deployment | More design/testing than a thin adapter; model-provider and publisher need spikes |
| **B. Native MCP Accelerator** | Register the SAM MCP endpoint, disable risky tools by default, add setup/diagnostics and native model provider | Smallest codebase; benefits from A0’s MCP schemas/media/timeouts | No UDS in A0 MCP; credentials/project scope constraints; generic gateway remains coarse; weaker consent UX |
| **C. Sovereign Appliance** | Ship an opinionated A0 + `sam-node` + `sam-box` deployment with the plugin as control UI | Strongest network boundary and clearest security story | Coupled to post-release SAM capabilities; harder Plugin Index install; greater operational burden |

## Recommended milestone shape if Approach A is approved

This is sequencing, not yet the implementation plan.

1. **Compatibility spike:** tested-version matrix; HTTP/UDS client; MCP and inference probes; Docker addressing; auth/error taxonomy.
2. **Read-only explorer:** onboarding, Capability Passport, Observatory, discovery/describe, schema cache, safe diagnostics.
3. **Guarded delegation:** destination-aware allowlists, risk classification, approval leases, duplicate-risk handling, audit trail.
4. **Native cognition:** SAM model provider, model discovery, resilient versus named routes, streaming/tool-call compatibility tests.
5. **Embassy publisher:** bounded inbound broker, project/profile mapping, rate/time/attachment limits, service registration lifecycle.
6. **Sovereign mode:** capability-gated deployment pack using `sam-box`, networkless A0, ingress/egress tests, rollback and upgrade playbook.

## Non-negotiable acceptance principles

- No install, OIDC join, mesh enrollment, peer connection, service publication, or sensitive-data transmission initiated silently by the model.
- One secret source; no node token in ordinary plugin config, model tool arguments, responses, logs, or chat history.
- Default deny for generic remote execution, pubsub, peer connection, recent logs, and inbound publication.
- Exact canonical service/tool names retained from discovery; no fabricated aliases.
- Remote content treated as untrusted; policy controls the next action as well as the current call.
- Side-effecting remote tools assumed non-idempotent unless proven otherwise; SAM retry ambiguity is visible.
- Automatic inference routing never presented as exact recipient disclosure.
- Feature claims derived from runtime probes and a maintained compatibility matrix, not from SAM’s nominal MCP server version.
- `a2a`, real peer messaging, semantic search, and full OpenAI compatibility not claimed until supported and verified.
- Plugin disable/uninstall has an explicit daemon, registration, cache, and secret-reference cleanup story.

## Decision gate

The next Superpowers design pass should lock one distribution target before defining components and interfaces:

- **Community plugin + optional companion deployment pack** (recommended)
- **Community plugin only**
- **Private/local integration optimized for one deployment**

After that choice, the approved design should be written as a Superpowers specification and only then expanded into a test-first implementation plan with exact files, tasks, validation commands, and commit boundaries.

## Primary source index

### Agent Zero

- [README at audited commit](https://github.com/agent0ai/agent-zero/blob/6a6cecff8527b164668c7a6ab2f76b6b1ed7cfa1/README.md)
- [Plugin architecture contract](https://github.com/agent0ai/agent-zero/blob/6a6cecff8527b164668c7a6ab2f76b6b1ed7cfa1/plugins/AGENTS.md)
- [Plugin creation workflow](https://github.com/agent0ai/agent-zero/blob/6a6cecff8527b164668c7a6ab2f76b6b1ed7cfa1/skills/a0-create-plugin/SKILL.md)
- [Plugin discovery/config implementation](https://github.com/agent0ai/agent-zero/blob/6a6cecff8527b164668c7a6ab2f76b6b1ed7cfa1/helpers/plugins.py)
- [MCP client implementation](https://github.com/agent0ai/agent-zero/blob/6a6cecff8527b164668c7a6ab2f76b6b1ed7cfa1/helpers/mcp_handler.py)
- [MCP server implementation](https://github.com/agent0ai/agent-zero/blob/6a6cecff8527b164668c7a6ab2f76b6b1ed7cfa1/helpers/mcp_server.py)
- [Tool policy implementation](https://github.com/agent0ai/agent-zero/blob/6a6cecff8527b164668c7a6ab2f76b6b1ed7cfa1/helpers/tool_policy.py)
- [Plugin model-provider merge](https://github.com/agent0ai/agent-zero/blob/6a6cecff8527b164668c7a6ab2f76b6b1ed7cfa1/helpers/providers.py)

### SAM

- [Documentation home](https://sam-mesh.dev/docs/)
- [Development](https://sam-mesh.dev/docs/development/)
- [Agent architecture](https://sam-mesh.dev/docs/agent-architecture/)
- [Quick Start](https://sam-mesh.dev/docs/quickstart/)
- [Agent usage](https://sam-mesh.dev/docs/user/agent-usage/)
- [Running agents](https://sam-mesh.dev/docs/user/running-agents/)
- [Node configuration](https://sam-mesh.dev/docs/user/node-configuration/)
- [Policy reference](https://sam-mesh.dev/docs/development/policy/)
- [Sidecar implementation](https://github.com/google/sam/blob/3224aae8dc962d6e8d4a83c4fa1f2d3e84c6db0f/internal/node/sidecar.go)
- [MCP server implementation](https://github.com/google/sam/blob/3224aae8dc962d6e8d4a83c4fa1f2d3e84c6db0f/internal/node/mcp.go)
- [OpenAI-compatible facade](https://github.com/google/sam/blob/3224aae8dc962d6e8d4a83c4fa1f2d3e84c6db0f/internal/node/openai_facade.go)
- [Release comparison: alpha.7 to audited main](https://github.com/google/sam/compare/v0.1.0-alpha.7...3224aae8dc962d6e8d4a83c4fa1f2d3e84c6db0f)
