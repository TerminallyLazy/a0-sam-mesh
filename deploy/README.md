# Sovereign deployment: experimental and blocked

This directory is a reviewable topology and capability gate. It is **not an operational
network sandbox**. The gate and bootstrap intentionally exit before Agent Zero starts.
No successful negative-network certification has been recorded.

The Compose template separates node, agent and UI socket volumes. The Agent Zero service
has no general network interface, does not mount the node socket or token, and has only
TUN/NET_ADMIN for a future certified bootstrap. The UI gateway has an internal network and
forwards only to its Unix-socket upstream. Static configuration tests do not prove these
runtime properties.

Set operator-verified image digests for `SAM_IMAGE` and `SAM_BOX_IMAGE` before validating
Compose. No guessed SAM registry images are supplied. An A0 image must contain the tested
framework runtime. Merely making `docker compose config` succeed does not enable startup.

Required work before activation:

- Test the published SAM binary and its bundle/issuer/audience/egress contracts.
- Pin and exercise a TUN-to-HTTP-CONNECT translator against the actual agent socket. There
  is no certified translator/bootstrap in this pack.
- Add and test the in-namespace loopback-to-UDS WebUI bridge and gateway WebSocket handling.
- Demonstrate approved-name success and rejection of unapproved hostnames, literal IPs,
  UDP, external DNS, node socket access, credential access and UI-gateway bypass.
- Exercise credential expiry/rotation, restart, drain, withdrawal, upgrade and rollback.
- Only then replace the blocked gate with an authenticated, reproducible certification path.

Current SAM source contains ingress and credential flags; older documentation claiming their
complete absence is obsolete. They remain **unverified here**. Never use proxy environment
variables, a normal agent network, an unverified bundle, or a shared node credential as a
substitute for the missing boundary.
