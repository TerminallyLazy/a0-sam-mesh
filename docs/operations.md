# Operations runbook

## Starting safely

Install into the intended Agent Zero framework and enable the plugin only for the desired
scope. Local mesh setup runs through `hooks.py` on install and when saved in settings;
there is no Execute action. Observe installation, startup and authenticated status in the
Observatory. Existing-node connections remain available in settings. Managed identities are
retained at `/a0/usr/sam_mesh/managed` across stop, update and uninstall. Loopback listeners
are private to the Agent Zero runtime; the plugin does not advertise services automatically.

Keep Explorer until the catalog and exact schemas are understood. Use the protected form for
non-public payloads. Approval records are temporary; keep the redacted audit as evidence, not
an exported payload or bearer. Discovery is partial and may become stale.

## Emergency and resume

Open Observatory and choose Emergency disconnect, then Disconnect now. It operates locally
before transport/secret resolution. Inspect `stopped` and any cleanup/audit degradation.
Already-admitted work may complete; compare remote state before retrying a mutation.

After correcting configuration, open Node, type `RESUME`, and resume the scope. It clears the
stop only after revoking profile leases and recording the request. Old decisions remain
invalid across all chats in that project/profile. Settings edits alone cannot clear a stop.

## Restart, upgrade and rollback

1. Disconnect affected scopes and wait for admitted calls to finish or record uncertain outcomes.
2. Stop the Agent Zero framework. Preserve its private `/a0/usr` data and SAM identity. Back up
   the plugin code and private plugin state with owner-only access; do not publish state backups.
3. Replace only `/a0/usr/plugins/sam_mesh` with the reviewed version. Keep plugin configuration
   and user data separate. Never overlay the enclosing Agent Zero checkout as the plugin.
4. Start the framework, verify Explorer discovery and the stop state, then explicitly resume
   intended scopes. Restart destroys the encryption key, so obtain fresh approvals.
5. To roll back, stop the framework and restore the previous plugin code. Do not downgrade or
   delete state databases to revive an approval. Compare the database contract before rollback.

A process crash can leave an invocation slot occupied. There is no automatic slot reset:
remote outcome reconciliation and an operator recovery procedure are still required. Resume
preserves active slots and quotas. Do not edit the database to bypass an uncertain mutation.

## Embassy publication

Start from an existing project/profile with SAM Mesh enabled. Review the immutable service
and acknowledge **PUBLISH** in Observatory. A healthy broker is explicitly
`healthy_not_published`; the operator must apply the reviewed static service declaration
and verify it from another enrolled peer. SAM has no dynamic registration API.

For normal withdrawal, remove the SAM node declaration and restart that node before closing
the broker. Emergency closure stops new admission immediately and reports operator withdrawal
pending. Cached advertisements may remain until expiry. Drain waits within its deadline,
cancels remaining work and removes ephemeral contexts. Plugin disable, changed scope or
revoked inbound permission also stops new admission. Restart never silently republishes.
Follow [Embassy operations](embassy-operations.md) for the signing gateway and trust mounts.

## Sovereign deployment

Use the optional pack only on a Linux host whose full runtime certification reports support.
Prepare the pinned read-only Agent Zero source, preserve the external user volume, and supply
separate operator credentials and public certification paths. The tested Docker Desktop
LinuxKit kernel is unsupported. Never add an ordinary agent network, unverified credentials,
a node token mount or Docker socket to bypass a failed gate.

[Sovereign operations](sovereign-operations.md) covers issuer/audience verification, explicit
named egress, isolated UI ingress, renewal, restart and state-preserving rollback. The host's
receipt expires after 24 hours and after a boot or immutable-input change; rerun certification.
The rollback script disables SAM Mesh before restoring ordinary Agent Zero networking and
preserves user data and SAM identity. It does not revive approvals or enroll a new identity.
