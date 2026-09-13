# Native Agent Zero community integration

Verified 2026-09-13 against the unmodified Agent Zero framework at
`b1cbd1f960a1a5c4482b324dcff4742aa67b7a51`, using framework Python 3.12.4 from
the digest-pinned image listed in [compatibility](compatibility.md). Native packaging
checks and live mesh acceptance have separate receipts; see [release readiness](release-readiness.md).

## Native integration

The ZIP installs through `_plugin_installer.helpers.install.install_from_zip` as
an ordinary copy at `/a0/usr/plugins/sam_mesh`. No core patch, persistent symlink,
custom server, dependency installation, or import-path modification is required.
The test runtime uses a fresh, copied framework and disposable user state.

[The machine-readable report](native-community-verification.json) records passing
checks against actual framework discovery, installation, APIs and removal:

- Native plugin-list metadata, Open screen, settings, README and Execute discovery.
- Root MIT license discovery and exact license text returned by the protected document API.
- Global, profile, project, and project/profile settings with inherited fallback.
- Save hooks reject raw-token fields without overwriting the previous configuration.
- All nine Tool subclasses, matching tool prompts, plugin skill and native Python extensions, including the specialist execution boundary.
- Chat-provider merging and canvas extension discovery.
- Authentication and CSRF through the real `UiServerRuntime` API dispatcher.
- Independent scoped activation; disabled tools, inference hooks, canvas and protected APIs.
- Offline emergency disconnect, re-enablement, global disable and provider removal.
- Native uninstall removes the installed copy and scoped plugin-owned assets.

The host enables newly installed plugins by default; `always_enabled: false`
allows ordinary toggling. Explorer, denied remote tools, zero call quota, and all
feature flags off remain the default authority. Scoped activation remains
independent of global activation, as in other Agent Zero community plugins.

## Native UI

`webui/main.html` supplies the plugin list's Open action. `webui/config.html`
inherits `config` and `context` from the host's `$store.pluginSettingsPrototype`.
The small settings store attaches its Observatory action to that modal's context;
Agent Zero owns scope selection, persistence, reset, and activation. The action
requires saved settings and an active chat. The Observatory operates on that
chat's saved passport, not an arbitrary settings scope selected in the modal.

Browser verification used the real host `plugin-settings.html`, prototype store,
component loader, Alpine lifecycle directives, notifications, API routes and an
installed plugin copy. Saving a loopback endpoint, reopening the settings,
opening Observatory, and clearing unsent arguments after closing/reopening all
passed. The wrapper selected a disposable chat; WebSocket transport and the full
chat boot sequence were outside this browser check. No SAM socket was present,
so the node probe correctly remained unavailable.

## Storage prerequisite

The framework `usr/` directory and intermediate state directories must be owned
by the framework account and not writable by group or others. SAM retains its
strict no-symlink and inode checks; it creates its private state directory with
mode 0700 and database with mode 0600. The disposable test initially had a 0775
`usr/`; the guard rejected it. The test setup was corrected to 0755, matching the
operator checkout. The plugin does not change permissions on framework-owned
parent directories. Inspect ownership and permissions if controls report storage
unavailable; do not broaden database access to silence the error.

## Community listing

The standalone plugin is distributed under the [MIT license](../LICENSE), matching
Agent Zero's license type. The root `LICENSE` is included in the installable ZIP,
discovered by the Plugin Hub, and returned intact by the native license-document
API. The verifier rejects an archive that omits it. The license and native
packaging requirements are complete.

The public repository is [TerminallyLazy/a0-sam-mesh](https://github.com/TerminallyLazy/a0-sam-mesh).
The [community index rules](https://github.com/agent0ai/a0-plugins#submitting-a-plugin-pull-request)
require a separate `plugins/sam_mesh/index.yaml` containing `title`, `description`, and
`github`. Its folder name must exactly match root `plugin.yaml`. The contribution contains
only that metadata and the square 8,108-byte `thumbnail.webp`; no runtime source is copied
into the index. Upstream maintainer review and merge determine listing availability.

## Reproduce native installation checks

Use a disposable framework copy with an empty SAM installation and secure `usr/`
permissions. Do not run this verification against normal user state: it installs,
changes fixture settings and activation, and removes the candidate again.

```sh
cd /a0
touch .sam-community-verification
PYTHONPATH=/a0 PYTHONDONTWRITEBYTECODE=1 LITELLM_LOCAL_MODEL_COST_MAP=True \
  /opt/venv-a0/bin/python /tmp/verify-community.py /tmp/sam-mesh.zip \
  --report /tmp/native-community-verification.json
```

Copy `scripts/verify-community.py` to `/tmp/verify-community.py` first. The script
refuses an existing SAM installation and preserves the supplied ZIP. The marker
is an explicit assertion that the whole runtime is disposable.
