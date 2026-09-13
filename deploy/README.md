# Sovereign deployment

This optional pack confines Agent Zero to a published `nano-init` TUN and a
credential-verified `sam-box` boundary. It remains **unavailable on an uncertified
host**. A successful help probe, a static Compose check, or a receipt from another
host does not enable it.

The supported command contract is SAM `v0.1.0-alpha.9`:

```text
nano-init run <boundary-socket> <command> [args...]
sam-box run --socket <private-socket> --sidecar-socket <node-socket> \
  --bundle <bundle> --credential-issuer <issuer> --credential-audience <audience>
```

`nano-init` embeds tun2connect; a separate tun2socks executable is neither used nor
accepted. Its isolation assertion stays intact. Docker Desktop's tested
`7.0.12-linuxkit` kernel creates fallback tunnel interfaces even with
`--network none`; the published binary refuses that namespace. Use a Linux host
whose actual runtime certification passes. Do not delete interfaces, weaken the
check, or relabel the adapter-only diagnostic as TUN certification.

The standard bundle is egress-only. Secret injection and automatic credential
rotation are disabled. Optional Embassy ingress uses its own authenticated UDS
contract; it is not enabled through this pack's `serves` field.

Read [the operations runbook](../docs/sovereign-operations.md) before provisioning.
The Compose defaults require explicit source, binary, image, user-volume,
credential and certification paths. The checked-in bundle contains no credential
and cannot start. No identity is enrolled automatically.

Run the disposable certifier with immutable inputs, after verifying the published
release checksums and the upstream Agent Zero source archive:

```sh
docker build -t sovereign-ui-network -f deploy/ui/Dockerfile .
UI_IMAGE=$(docker image inspect sovereign-ui-network --format '{{.Id}}')
python3 deploy/scripts/certify-runtime.py \
  --binary-dir /srv/sam/bin \
  --image 'agent0ai/agent-zero@sha256:db4617788520154de9173c59b581f4f0c6ef7a6c75c01d4c2fbc689793896b10' \
  --firewall-image "$UI_IMAGE" \
  --a0-source-tar /srv/agent-zero/upstream.tar.gz \
  --output /srv/sam/certification/receipt.json
```

Only exit status 0 and `supported: true` certify the complete matrix. Use
`--adapter-only` to diagnose actual verified UDS routing, identity expiry and UI
isolation on a host where TUN cannot start; this always reports unsupported.
The certifier creates and removes only randomly named `sam-stable-sovereign-*`
containers, networks and volumes. It creates disposable credentials and a private
SAM mesh inside its own infrastructure container.
