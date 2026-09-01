from pathlib import Path
import yaml


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
