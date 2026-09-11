# Operations runbook

## Starting safely

Install into the intended Agent Zero framework and enable the plugin only for the desired
scope. Confirm Node, endpoint and passport before using Catalog. Use explicit Docker addresses;
never infer a running node from a source checkout. `execute.py --help` lists local diagnostics.
No diagnostic performs enrollment or writes a node configuration.

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

The UI currently validates a declaration and explains why publication is closed. It cannot
start or advertise a broker. Before enabling this track, provide an authenticated final hop
from SAM, enforce the dedicated profile/tool boundary, and verify the three MCP methods.
SAM currently requires administrator-managed node service configuration; a generated plan
is not an applied or advertised service.

The lifecycle controller's required order is health → observed advertisement → publish.
Closure withdraws advertisement before stopping the broker. A failed withdrawal is reported
as `closed_withdrawal_pending`. Drain rejects new work, waits within its deadline, cancels
remaining work and removes ephemeral contexts. These component transitions have local tests;
there is no live publication/upgrade/rollback certification yet.

## Sovereign deployment

Do not start the experimental pack for production. Its capability gate exits nonzero and its
bootstrap refuses to substitute ordinary networking for certified confinement. Follow
`deploy/README.md` to understand the missing certification work. Never add a normal agent
network, `--insecure-unverified-bundle`, a node token mount, or Docker socket access to get it
past the gate.
