# Verification

Use the Agent Zero **framework** interpreter and Linux. UDS descriptor checks and install
fixtures need procfs and Linux `O_PATH`/`linkat`; the separate Python agent runtime is insufficient.

```bash
/opt/venv-a0/bin/python -m pytest -q
ruff check .
ruff format --check .
node --check webui/observatory-store.js
node --test tests/test_observatory_store.mjs
python scripts/scan-secrets.py
/opt/venv-a0/bin/python scripts/compatibility-report.py
```

Development tooling used: pytest 8.4.2 and Ruff 0.16.0. Pytest and its existing pure-Python
support packages were mounted read-only from an existing local cache; no dependencies were
installed. Pytest plugin autoload was disabled. Async tests use `IsolatedAsyncioTestCase`.

For host integration, `tests/test_host_integration.py` and installed-wrapper tests use a
temporary plugin namespace, the actual framework under `/a0`, and `/opt/venv-a0/bin/python`.
They keep real provider merging, native model transport, Tool/Response imports and Flask
routing. Local sidecars replace SAM, and no real model prompt leaves the test environment.
The fixture install helpers refuse to replace existing plugin paths and remove only their
own pinned symlink.

The full release check uses a clean source snapshot of all current Git-listed source files,
without `.git`, caches, user state or prior runtime artifacts. The published ZIP is built
with `git archive` from the release commit.
Do not equate the snapshot with live acceptance against an enrolled mesh.

## Three passes

1. **Component correctness:** configuration/passports, denial precedence, risk/schema limits,
   hash/lease binding, replay/expiry, audit integrity, TCP/UDS and error contracts, plus lint.
2. **Integration and adversarial:** installed framework imports, provider enable/disable,
   authenticated API routing/CSRF, streaming/non-streaming/tool output, destination approval,
   transport substitution, origin-bound sessions, stale UI response rejection and withdrawal
   ordering. Browser testing uses the shipped Alpine runtime with an explicit local fixture
   API; it is not a running Agent Zero WebUI/SAM combination.
3. **Operational proof:** clean source suite, pattern scan and sentinel leakage assertions,
   dependency report, offline stop/resume and warm-path latency. Live SAM release/main, full
   host restart/disable/drain, published Embassy and Sovereign network tests remain outstanding.

The pattern scanner reports filenames and rule names only. It cannot prove arbitrary text
contains no secret. Separate tests assert that fixture credentials and protected payloads do
not appear in server outputs, wrapper logs, persisted plaintext decisions or redacted audit.

The audit-retention tests deliberately exercise thousands of rows and may take several
minutes. Preflight latency excludes SAM discovery and uses warm local stores. The 150 ms
preflight and 500 ms offline-stop limits are local test budgets, not production SLAs.

## Release reproduction

CI in `.github/workflows/test.yml` runs static checks, all Python tests, and actual ZIP
installation in the pinned Agent Zero framework image. It checks both the pinned upstream
revision and upstream `main`; the fixture runtime is disconnected from external networking
before tests run. Test tools are installed only in that disposable CI environment.

Build the same installable source archive from a reviewed release commit:

```sh
git archive --format=zip --output=sam-mesh-1.0.0-alpha.1.zip v1.0.0-alpha.1
sha256sum sam-mesh-1.0.0-alpha.1.zip
```

The GitHub release carries the exact verification receipt and archive checksum. A public
alpha or a passing CI run does not certify live mesh behavior or unavailable tracks.

## Native community installation

Use the disposable-runtime procedure in [native-community.md](native-community.md).
It exercises an actual installed copy and unmodified host discovery and management,
without replacing framework loaders. The native settings browser check also uses
the host settings prototype, component loader, save route and destroy lifecycle.
