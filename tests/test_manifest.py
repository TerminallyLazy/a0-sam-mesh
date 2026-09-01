from pathlib import Path

import yaml

from tests.conftest import PLUGIN_ROOT, _install_plugin


def test_manifest_is_installable_and_fail_closed():
    root = Path(__file__).parents[1]
    manifest = yaml.safe_load((root / "plugin.yaml").read_text())
    defaults = yaml.safe_load((root / "default_config.yaml").read_text())
    assert manifest == {
        "name": "sam_mesh",
        "title": "A0 SAM Mesh Embassy",
        "description": (
            "Governed SAM tools, mesh inference, and optional sovereign "
            "Agent Zero service publication."
        ),
        "version": "1.0.0",
        "settings_sections": ["mcp", "external"],
        "per_project_config": True,
        "per_agent_config": True,
        "always_enabled": False,
    }
    assert defaults["schema"] == "a0.sam.config/v1alpha1"
    assert defaults["passport"]["mode"] == "explorer"
    assert defaults["features"] == {
        "remote_calls": False,
        "mesh_inference": False,
        "inbound_publication": False,
        "raw_mcp": False,
    }


def _fake_a0_checkout(tmp_path: Path) -> Path:
    checkout = tmp_path / "agent-zero"
    helper = checkout / "helpers" / "plugins.py"
    helper.parent.mkdir(parents=True)
    helper.write_text("# Agent Zero plugin helper marker\n")
    return checkout


def test_plugin_install_creates_symlink_and_removes_it_on_teardown(tmp_path: Path):
    checkout = _fake_a0_checkout(tmp_path)
    plugin_path = checkout / "usr" / "plugins" / "sam_mesh"

    with _install_plugin(checkout) as installed_checkout:
        assert installed_checkout == checkout
        assert plugin_path.is_symlink()
        assert plugin_path.resolve() == PLUGIN_ROOT

    assert not plugin_path.exists()
    assert not plugin_path.is_symlink()


def test_plugin_install_refuses_to_replace_existing_path(tmp_path: Path):
    checkout = _fake_a0_checkout(tmp_path)
    plugin_path = checkout / "usr" / "plugins" / "sam_mesh"
    plugin_path.mkdir(parents=True)

    try:
        with _install_plugin(checkout):
            raise AssertionError("installation replaced an existing path")
    except RuntimeError as exc:
        assert "Refusing to replace existing plugin path" in str(exc)
    else:
        raise AssertionError("installation did not reject an existing path")

    assert plugin_path.is_dir()
    assert not plugin_path.is_symlink()


def test_plugin_teardown_preserves_replacement_path(tmp_path: Path):
    checkout = _fake_a0_checkout(tmp_path)
    plugin_path = checkout / "usr" / "plugins" / "sam_mesh"
    replacement = tmp_path / "replacement"
    replacement.mkdir()

    with _install_plugin(checkout):
        plugin_path.unlink()
        plugin_path.symlink_to(replacement, target_is_directory=True)

    assert plugin_path.is_symlink()
    assert plugin_path.resolve() == replacement.resolve()


def test_a0_checkout_fixture_yields_installed_checkout_and_cleans_up(
    tmp_path: Path, monkeypatch
):
    from tests.conftest import a0_checkout

    checkout = _fake_a0_checkout(tmp_path)
    plugin_path = checkout / "usr" / "plugins" / "sam_mesh"
    monkeypatch.setenv("A0_CHECKOUT", str(checkout))
    fixture_body = a0_checkout.__pytest_wrapped__.obj()

    assert next(fixture_body) == checkout.resolve()
    assert plugin_path.is_symlink()
    try:
        next(fixture_body)
    except StopIteration:
        pass
    else:
        raise AssertionError("a0_checkout yielded more than once")

    assert not plugin_path.exists()
    assert not plugin_path.is_symlink()
