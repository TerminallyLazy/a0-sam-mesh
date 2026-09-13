# Sovereign operations

Sovereign starts only after complete certification on the deployment host. Current
local evidence verifies the published boundary, its adapters, native WebUI and
rollback, but does not certify TUN on Docker Desktop `7.0.12-linuxkit`. The exact
published `nano-init` refuses the extra kernel fallback interfaces there. The pack
keeps this failure visible and never substitutes proxy variables for confinement.

## Provision and certify

Use the published SAM `v0.1.0-alpha.9` binaries for the host architecture and verify
its release checksum file. The tested Linux ARM64 archive SHA-256 is
`cf0d2ae56674ba5a4f57165285b230da602a637dc698109145a8a0a0f688b02d`;
source revision is `077a43e2e89e544bc6ecfbf6b4607706490592ad`.
The published `agent-zero:ready` runtime image does not contain the A0 core source.
Provide the verified upstream source directory as `A0_SOURCE_DIR`; Compose mounts
it read-only, with separate writable `/a0/usr` and `/a0/tmp` volumes. Ensure the
user volume's `usr` and `usr/plugins` directories are mode 0755. The community
plugin must already be installed in that user volume. Before mounting source, run
`python3 deploy/scripts/prepare-source.py /srv/agent-zero/source`. This creates only
the native knowledge directories; the capability gate refuses unprepared source.
The default command includes `--dockerized=true`, which keeps native prompt helpers
local instead of attempting development RPC. Local model caches run offline.

Copy `deploy/compose/.env.example` to an operator-managed environment file and set
all paths explicitly. Never put workload credentials in that environment file.
Build `deploy/ui/Dockerfile` and pin its resulting immutable image ID as
`UI_NETWORK_IMAGE`; certification records that same reference. Pin `A0_IMAGE` by
digest. The firewall builder installs iptables inside the image only.

Run the command in `deploy/README.md` on the actual deployment host. Freeze the
pack and binaries while it runs. Receipts are mode 0600, contain hashes/results
rather than credentials, expire after 24 hours, and are bound to the host's boot
ID, kernel, exact binaries, A0 source and deployment files. A Docker restart or
upgrade requires recertification. CI receipts are release evidence; copying one
to another host cannot enable that host.

Provision the existing `node-state` volume through the operator's SAM enrollment
workflow before starting this stack. The pack never auto-enrolls a node. The
boundary requires an enrolled node's `/v1/models` endpoint before opening its
public socket, excluding the unenrolled sidecar's enrollment MCP surface. The
node's signed mesh role must also grant the exact bundle agent ID and requested
mesh services: a valid workload JWT does not grant permission to impersonate an
arbitrary mesh agent. The test mesh seeds an exact `a0.cert.test` grant and
`mcp://sovereign_probe` service grant, including the equivalent signed Datalog
fact for published control planes that do not persist `allowedAgents`.

The mode-0600 bundle uses the actual published `version: v1`, nested `agent`
identity and `egress.allow` schema. Its `agent.credential` points to a mode-0600
JWT file in the box's `/run/credentials` mount. These files and the certification
receipt must be owned by the container runtime UID (root/UID 0 in the shipped
Compose), with protected parent directories. Provision ownership explicitly on
the operator host; changing permissions alone does not change ownership. Issuer and audience come from
operator Compose values, not the bundle. The published box verifies signature,
issuer, audience and subject. The pack additionally requires finite expiry with
at least 30 seconds remaining. The checked-in sample is intentionally unusable.

## Start and inspect

From a shell with the operator environment loaded:

```sh
sh deploy/scripts/preflight.sh
docker compose -f deploy/compose/docker-compose.sovereign.yml up -d
docker compose -f deploy/compose/docker-compose.sovereign.yml ps
```

Preflight checks immutable image references, the explicit user volume, free
loopback UI port, rendered Compose and the exact-host certification gate. Runtime
startup validates the actual credential, socket ownership and namespace.
`guest_probe()` lets the native plugin verify public certification, read-only
mounts, core/binary hashes, exactly `lo` and `tun0`, both default routes,
no-new-privileges and only NET_ADMIN capability, no container-control socket, and actual
boundary admission without accessing the node socket or node credential.

Agent Zero receives only its read-only boundary socket, separate UI socket,
public certification, source/scripts, nano-init and user/runtime volumes. It has
`network_mode: none`; no node socket, private box socket or credentials are
mounted. The optional Embassy override adds a distinct ingress socket and public
trust key, under its own authenticated contract.

The public boundary accepts named TCP CONNECT only. External names must be exact
lowercase DNS names in the bundle; an empty list denies external egress. Literal
IPs, wildcard policy, TCP DNS and all UDP upgrades are refused. The adapter accepts the published Go client's
fixed `User-Agent: Go-http-client/1.1`, strips it before forwarding, and refuses
general header extensions. Canonical mesh
service names retain underscores. The published box restricts `mesh.sam.alt` to
its inference and MCP facade; node administrative paths remain inaccessible.
Virtual DNS answers can be synthesized locally even when a caller names an
external DNS resolver: certification therefore checks zero packets at an
external DNS witness rather than treating any DNS answer as leakage.

## UI isolation

The UI bridge forwards bytes only to the fixed Agent Zero loopback port. It
preserves HTTP/WebSocket traffic and leaves application authentication and CSRF
to the unmodified native host. The external gateway has no node or boundary
socket and has all capabilities dropped.

Docker 29 discards published ports for `internal: true` networks. The pack uses a
dedicated `a0-ui-network` namespace initializer instead: it installs IPv4 and IPv6
DROP policies, permits only incoming TCP 8080 and established replies from that
port, then drops every capability before waiting. The gateway joins that
namespace only after readiness. It cannot initiate IPv4, IPv6 or DNS traffic.
Neither service receives a Docker socket, user data, or a network-administration
socket. Host binding is loopback-only; external access requires a separately
reviewed authenticated operator ingress.

## Expiry, restart and emergency closure

The public adapter closes admission and existing streams before workload expiry
(30-second margin). It also drains when the credential or bundle bytes change,
protected socket ownership/modes/inodes change, the node socket is replaced or
sam-box exits. Monitoring is every 200 ms; box termination is bounded to five
seconds. Connections are capped at 64 and 300 seconds. UI streams have a separate
one-hour bound. The agent supervisor stops the UI bridge if A0 exits and stops A0
if its bridge exits.

There is no automatic credential rotation. Drain, replace the operator bundle or
credential, and restart the box and agent in a fresh namespace. Never select
`--insecure-unverified-bundle`, widen egress, or re-run nano-init inside a namespace
whose existing routes belong to a prior invocation.

```sh
sh deploy/scripts/drain.sh
```

Drain disables the native plugin and clears scoped enable overrides, then stops
UI ingress, Agent Zero, box, node and the UI network keeper. Configuration, audit
and user files remain on the existing volume. Even if native plugin disable
fails, emergency drain attempts every stop and reports an error for inspection.
It never removes volumes or resets node identity.

## Roll back and upgrade

```sh
sh deploy/scripts/rollback.sh \
  --ordinary-compose /srv/agent-zero/ordinary-compose.yml \
  --export /srv/sam/rollback-redacted.json
```

Rollback requires exactly the same explicit named `/a0/usr` volume in both
rendered Compose configurations. It disables the plugin before ordinary startup,
exports only redacted operational metadata, stops Sovereign, and starts the
explicit ordinary stack. Full settings and audit remain intact in the user
volume; they are not copied into a potentially exposed export file. A failed
native disable closes Sovereign and refuses ordinary startup. Re-enabling the
plugin after rollback is an explicit operator action.

Upgrade by draining, retaining both named state volumes, verifying new artifacts,
re-running certification and preflight, and recreating the services. Never use
`down --volumes`, `docker volume prune`, or `sam-node reset` as part of this pack's
lifecycle. The runtime harness exercises real native plugin disable, ordinary
Agent Zero startup, user-file preservation, node-state volume preservation and
actual credential/network negative cases. It also requires a full native
`context.communicate` message on read-only source with all capabilities dropped,
through prompt/extensions and `ResponseTool.break_loop`. That startup regression
uses a deterministic model-output fixture and needs no model credential; named
mesh network acceptance is exercised separately against the real SAM processes.

Certification finishes with a fresh actual nano-init guest using the production
read-only source, public receipt and nano binary mounts, the native installed
plugin, and its exact credentialless mesh facade configuration. It must discover
the disposable model through `SamClient`, invoke the native `sam_mesh` provider
across the real mesh, and complete `context.communicate` with one governed
admission and `ResponseTool.break_loop`. The internal baseline receipt used to
exercise this final step is never exported and cannot pass the operator deployment
gate; only the completed final receipt can enable deployment.
