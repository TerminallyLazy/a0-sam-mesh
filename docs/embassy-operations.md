# Embassy operations

Embassy publishes three bounded MCP tools: `service_info`, `ask_specialist` and `finish_session`. Start from a real Agent Zero project and agent profile, enable SAM Mesh for that scope, select Embassy, enable reviewed publication, and list the exact allowed service names. The native Observatory reviews the immutable service definition before its **PUBLISH** acknowledgment starts the broker. The default mode remains Explorer.

## Trust boundary

Run the signing gateway beside `sam-node` in an exclusive operator network namespace. It binds only `127.0.0.1:7081`. Do not run Agent Zero, user code, unrelated containers, a general proxy, or a shell accessible to an agent in that namespace. Shared-host loopback alone does not authenticate SAM.

SAM's named HTTP route verifies the remote peer and replaces `X-Peer-Id`. The gateway signs that identity together with the request body, service, path, timestamp, nonce and the current broker challenge. Agent Zero verifies the signature on an owner-only Unix socket using a public key. It never receives the gateway's private key. Each broker incarnation changes its challenge, so captured requests cannot survive a restart. Caller cookies, authentication, asserted origin proofs and MCP session headers are not forwarded.

The native SAM MCP forwarding path loses caller attribution. It may probe initialization and tool schemas but cannot execute an anonymous Embassy tool. SAM Mesh recognizes the broker's `SAM Embassy HTTP v1: ` descriptor and invokes the exact `/sam/<peer>/mcp/<service>` route. This marker selects a transport; it does not establish trusted risk metadata. Unknown-risk calls still require single-use approval. Required labels are refused on this route because SAM has no equivalent HTTP label contract.

## Provision the gateway

Use three separate, non-overlapping, empty, owner-only directories for private signing material, public trust and the broker socket. None may be inside another; sibling directories such as the example below are suitable. This applies to the Linux host mount sources as well as their container destinations. The runtime user must own them; the supplied Agent Zero image runs as root. Run `scripts/prepare-embassy.py` in that same framework image with only those directories mounted and `--network none`. For example, from the plugin checkout:

```sh
# Create these directories on the Linux deployment host with the runtime owner's UID.
install -d -m 700 /srv/sam/embassy-private /srv/sam/embassy-public /srv/sam/embassy-socket

docker run --rm --network none --cap-drop ALL \
  -v "$PWD/scripts/prepare-embassy.py:/prepare.py:ro" \
  -v /srv/sam/embassy-private:/private \
  -v /srv/sam/embassy-public:/public \
  -v /srv/sam/embassy-socket:/socket \
  --entrypoint /opt/venv-a0/bin/python "$A0_IMAGE" /prepare.py \
  --private-dir /private --public-dir /public --socket-dir /socket
```

Before creating any key material, the command rejects equal or nested directory paths. On Linux it also reads `/proc/self/mountinfo` and compares filesystem backing roots, so binding nested host sources to seemingly separate `/private`, `/public` and `/socket` destinations is refused. Linux provisioning fails closed if that mount topology cannot be read. Keep this layout unchanged when starting the gateway and Agent Zero; do not add an alternate agent-readable mount of the signer directory. The command creates a stable Ed25519 identity, preserves it on repeat runs and refuses mismatched keys or unsafe permissions. It never prints keys. Mount `/srv/sam/embassy-private` only in the gateway at `/run/embassy-key:ro`. Mount `/srv/sam/embassy-public` in Agent Zero at `/run/sam-embassy-trust:ro`, and share `/srv/sam/embassy-socket` at `/run/sam-embassy` with Agent Zero writable and the gateway read-only. A Unix-socket volume must be local to the Linux Docker host; use Docker volumes on Docker Desktop, not a macOS host socket bind.

Run the gateway from a read-only copy of this plugin checkout:

```sh
/opt/venv-a0/bin/python -m helpers.embassy_gateway \
  --key-file /run/embassy-key/private.key \
  --broker-socket /run/sam-embassy/broker.sock --port 7081
```

For Sovereign, combine `deploy/compose/docker-compose.sovereign.yml` with `deploy/compose/docker-compose.embassy.yml`. Supply `EMBASSY_SIGNER_DIR`, `EMBASSY_TRUST_DIR`, `EMBASSY_SOCKET_DIR` and `EMBASSY_NODE_CONFIG` in addition to the certified Sovereign settings. The gateway shares only the operator node namespace; the networkless agent gets no node socket or signing key. This is a separate inbound MCP broker, not an unsupported MCP entry in sam-box's A2A-only `serves` contract.

## Publish, drain and withdraw

1. In the project's native SAM Mesh settings, select Embassy (or a certified Sovereign deployment), enable publication, and allow the exact service name. Save the settings.
2. Open the Observatory's Embassy tab, review the service's project, profile, persistence and limits, then acknowledge publication. The healthy broker is shown as `healthy_not_published`.
3. Copy its reviewed node fragment into the operator's SAM configuration. Preserve existing services and restart the operator node. A service named `research-desk` uses `type: mcp` and `target_url: http://127.0.0.1:7081/research-desk/mcp`.
4. Verify discovery and `service_info` from a different enrolled peer. Do not infer public reachability from a healthy local broker alone.
5. To withdraw normally, remove the node declaration and restart the node first, then drain/close the broker in the Observatory. For an emergency, close or disconnect immediately; admission stops even if a cached advertisement remains. Remove the operator declaration afterward. SAM's discovery caches may retain the old record until expiry.

There is no invented dynamic registration API. The UI reports that operator withdrawal is pending until the static configuration is changed. A process restart does not automatically republish services; the operator must review and start them again. Disabling the plugin, changing the owning scope or removing inbound permission revokes new admission; the maintenance loop drains revoked services. Existing calls have bounded shutdown, and unused contexts expire.

## Specialist scope

Version 1 permits the `response` tool only. Attachments, arbitrary files/URLs, shell tools, subordinate agents and changing project/profile are unavailable to an inbound specialist. The context uses the selected project's instructions and profile. Optional `isolated_chat` sessions are opaque, bound to the authenticated peer and immutable service, capped, rate limited and removed on finish, timeout or drain. The default is stateless. This scope is a tool boundary; full process/network confinement requires the separately certified Sovereign pack.

Live verification receipts cover real native `context.communicate`, real model output through the response tool, cross-peer and cross-service session rejection, native tool-policy enforcement, context/chat cleanup, gateway separation, spoof rejection, and a governed single-use call. See [verification](verification.md) and [Sovereign operations](sovereign-operations.md) for the exact supported runtime evidence.
