"""Exercise the native installer/config/uninstall hook dispatcher."""

import os
import subprocess
import sys
import textwrap


def test_native_hooks_create_only_managed_connections_and_stop_on_disable(a0_checkout):
    program = textwrap.dedent("""
        import copy, tempfile
        from pathlib import Path
        from unittest.mock import Mock, patch
        from helpers import plugins
        from usr.plugins.sam_mesh.helpers import managed_node, embassy_runtime, decisions
        from usr.plugins.sam_mesh.helpers.domain import Scope
        owner = Mock()
        owner.ensure.return_value = {"status": "starting"}
        owner.stop.return_value = {"status": "stopped", "identity_preserved": True}
        with patch.object(managed_node, "manager", return_value=owner), patch.object(embassy_runtime, "_runtime", None):
            defaults = plugins.get_plugin_config("sam_mesh")
            assert defaults["connection"] == "managed"
            assert plugins.call_plugin_hook("sam_mesh", "install")["status"] == "starting"
            assert owner.ensure.call_count == 1
            external = copy.deepcopy(defaults)
            external.pop("connection")
            plugins.call_plugin_hook("sam_mesh", "save_plugin_config", settings=external)
            assert owner.ensure.call_count == 1
            plugins.call_plugin_hook("sam_mesh", "save_plugin_config", settings=defaults)
            assert owner.ensure.call_count == 2
            # Only toggle files are redirected: dispatch and extension loading are native.
            with tempfile.TemporaryDirectory() as directory, patch.object(plugins, "determine_plugin_asset_path", side_effect=lambda name, project, profile, filename: str(Path(directory) / filename)):
                store = decisions.DecisionStore(db_path=Path(directory) / "approvals.sqlite3", trusted_root=directory)
                scope = Scope(project_name="", agent_profile="agent0", chat_id="lifecycle-test")
                pending = store.create(scope, {"message": "public lifecycle test"})
                admitted = store.begin_native(scope, 1)
                store.finish(scope, admitted)
                plugins.toggle_plugin("sam_mesh", False)
                assert owner.stop.call_count == 1
                try:
                    store.load(scope, pending)
                    raise AssertionError("pending authority survived plugin disable")
                except decisions.DecisionError as exc:
                    assert str(exc) == "decision_unavailable"
                assert not store.disabled(scope)
                try:
                    store.begin_native(scope, 1)
                    raise AssertionError("plugin disable reset the quota")
                except decisions.DecisionError as exc:
                    assert str(exc) == "session_quota_exceeded"
                plugins.toggle_plugin("sam_mesh", True)
                assert owner.ensure.call_count == 3
            plugins.call_plugin_hook("sam_mesh", "pre_update")
            plugins.call_plugin_hook("sam_mesh", "uninstall")
            assert owner.stop.call_count == 3
            print("native managed lifecycle passed")
    """)
    result = subprocess.run(
        [sys.executable, "-c", program],
        cwd=a0_checkout,
        env={**os.environ, "PYTHONPATH": str(a0_checkout)},
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
