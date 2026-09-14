# Stable release assessment

**SAM Mesh 1.0.1 · 2026-09-14**

SAM Mesh is a native Agent Zero community plugin. Embassy and Sovereign are selectable,
implemented modes; Explorer remains the default and grants no remote execution authority.
The live mesh and native specialist checks use real enrolled peers and real model output.
Sovereign additionally requires certification on the deployment host.

## Release scope

| Track | Supported behavior | Operating requirement |
| --- | --- | --- |
| Core / Observatory | Scoped passports, pinned TCP/UDS, bounded schemas, one-use unknown-risk approvals, quotas, redacted audit and offline disconnect | Explicit scope, service/data policy and approval |
| Cognitive Relay | Native SAM Mesh provider and destination-approved named requests | Compatible model, configured inference authority and positive call quota |
| Embassy | Signed caller identity, three-tool broker, native specialist contexts, scoped isolation, drain and cleanup | Exclusive operator signing gateway, reviewed PUBLISH action and applied static SAM registration |
| Sovereign | Published TUN/boundary, named TCP egress, separate isolated UI ingress, credential expiry/drain and state-preserving rollback | Matching complete, fresh Linux host certification and observed guest confinement |
| Native MCP / Raw MCP | Review-only compatibility assessment | Raw execution and automatic registration remain unsupported because host tool denials cannot constrain future unknown gateway tools |

## 1.0.1 repair

Native install and settings hooks now create a private local mesh and authenticated node.
Global disable, re-enable, startup, update and uninstall use hooks; there is no Execute
script or button. Identity and the private service configuration survive lifecycle changes.
Stopping invalidates sealed pending approvals without resetting quotas or emergency stops.

The live installation exposed two protocol defects missed by 1.0.0's fixture coverage:
SAM's health endpoints return plain-text `OK`, and a fresh MCP connection must initialize
before discovery. The repair accepts only the exact health response, verifies authentication
separately through `/v1/models`, and automatically initializes each MCP session. Real
published-binary tests now cover these paths, including wrong-token rejection.

The Observatory now anchors at the top of the side canvas, handles late chat restoration,
shows connection setup and empty catalog states, and opens native scoped settings. Live
native Tool-class checks verified status, models, local services and remote discovery.
The fresh local mesh starts with no advertised services. Embassy and Sovereign remain
selectable with their existing explicit deployment requirements.

The release's CI and receipt identify the exact tested commit and a new complete Sovereign
matrix. Prior model/Embassy evidence below belongs to 1.0.0 and is not relabeled as a new
1.0.1 live-model run.

## Prior live evidence (1.0.0)

- Real `gpt-6-astra` inference over two independently enrolled peers using released SAM
  `v0.1.0-alpha.9` and the then-current main `1966b79e7c6864876fc34722e78a050f1c23938c`, selected through
  the native `sam_mesh` provider and completed through the response tool with `break_loop`.
- Three-peer Embassy acceptance: native ZIP installation and publication controls, real
  specialist message completion, verified caller/session binding, cross-peer and cross-service
  rejection, native tool-policy enforcement, context/chat cleanup and drain.
- Live spoof overwrite and unsigned-forwarding denial; native discovered-schema preflight,
  one-use operator approval, actual specialist invocation and replay rejection. Static
  withdrawal and node restart preserve identity while the old route becomes unavailable.
- The complete 37-check Linux Sovereign matrix: real TUN, named mesh/external positives,
  denied addresses/DNS/UDP/admin routes, verified credential failures and expiry, socket/node
  restarts, isolated native UI/WebSocket, rollback and native guest model completion.
  The final guest starts through the shipped supervisor and passes the strict native gate
  in a fresh namespace. Both native model admissions and response-tool completion are observed.
- Full Python, native ZIP install/uninstall, actual Alpine behavior, Ruff and secret-pattern
  checks are enforced by [the release workflow](../.github/workflows/test.yml). Native tests
  run against both the pinned framework and current upstream main in disposable runtimes.
  Runtime changes require a new matching Sovereign certification.

The release includes sanitized JSON evidence, native installation receipts, the exact source
archive and SHA-256 checksums. The final release asset set and linked CI run identify the
commit actually shipped. A local fixture, CLI help output or an earlier candidate's receipt
is never substituted for a complete matching runtime result.

## Material limits

Sovereign is supported only on a host whose actual runtime certifier passes. The tested
Docker Desktop `7.0.12-linuxkit` kernel is unsupported because the published nano-init refuses
its extra fallback interfaces. Linux CI passed on `6.17.0-1022-azure`; its receipt cannot
activate another host. A deployment receipt expires after 24 hours and binds boot, kernel,
images, binaries, runtime plugin files, approval UI and read-only Agent Zero source.

Embassy v1 specialists have only the response tool. Project instructions and the chosen
profile are operator-selected; arbitrary files, URLs, attachments, shell and subordinate
agents are unavailable. Broker health is separate from mesh publication, and withdrawal
requires removing the operator's static declaration. Discovery caches may outlive withdrawal.
Pinned outbound Embassy routes are unavailable through Sovereign's restricted facade;
its optional inbound Embassy deployment uses a separate signed gateway and Unix socket.

The live OAuth-backed model supports the native JSON response-tool path but rejects
structured OpenAI function tools. Structured function transport and error cases are covered
by framework fixtures; universal live provider compatibility is not claimed. See
[compatibility](compatibility.md), [Embassy operations](embassy-operations.md), and
[Sovereign operations](sovereign-operations.md).

## Publication

The [1.0.1 release](https://github.com/TerminallyLazy/a0-sam-mesh/releases/tag/v1.0.1) contains
the installable ZIP and verification assets. The root manifest, native plugin layout,
README, MIT license and original logo are in the standalone repository.

The [existing Plugin Index contribution](https://github.com/agent0ai/a0-plugins/pull/547)
contains exactly `plugins/sam_mesh/index.yaml` and its square 8,108-byte thumbnail, using
only supported fields and five recommended tags. The official submission validator passes.
The contribution was merged into the official index on 2026-09-14. The index points to
the plugin repository, so this repair ships through the same native plugin update path.
