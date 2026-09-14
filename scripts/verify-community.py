"""Exercise a ZIP through the unmodified host in a disposable Agent Zero runtime.

Run with framework Python, PYTHONPATH=/a0 and cwd=/a0. Requires an explicit
/a0/.sam-community-verification marker; refuses an existing SAM installation.
No SAM node, model call, dependency installation or user credentials are needed.
"""

import argparse
import json
import os
import shutil
import tempfile
import uuid
from pathlib import Path


def verify(archive):
    from agent import AgentConfig, AgentContext
    from helpers.providers import ProviderManager
    from helpers.ui_server import UiServerRuntime
    from plugins._plugin_installer.helpers.install import install_from_zip

    from helpers import extension, files, login, plugins, projects, subagents

    root = Path(files.get_abs_path(""))
    if not (root / ".sam-community-verification").is_file():
        raise RuntimeError("Use a disposable framework with the verification marker")
    if plugins.find_plugin_dir("sam_mesh"):
        raise RuntimeError("Refusing to replace an existing SAM installation")
    if (root / "usr").stat().st_mode & 0o022:
        raise RuntimeError(
            "Verification requires a non-group/world-writable framework usr directory"
        )
    checks = []

    def check(condition, name):
        if not condition:
            raise AssertionError(name)
        checks.append(name)

    # The native installer consumes its uploaded archive. Preserve the caller's ZIP.
    with tempfile.TemporaryDirectory() as directory:
        uploaded = Path(directory) / "sam_mesh.zip"
        shutil.copyfile(archive, uploaded)
        result = install_from_zip(str(uploaded))
    check(result["success"] and result["plugin_name"] == "sam_mesh", "native_zip_install")
    installed = Path(plugins.find_plugin_dir("sam_mesh"))
    check(installed == root / "usr/plugins/sam_mesh", "community_install_root")
    check(not installed.is_symlink(), "installed_copy_without_symlink")
    check("sam_mesh" in plugins.get_plugins_list(), "native_discovery")
    item = next(
        p
        for p in plugins.get_enhanced_plugins_list(custom=True, builtin=False)
        if p.name == "sam_mesh"
    )
    check(
        item.is_custom
        and item.has_main_screen
        and item.has_config_screen
        and item.has_readme
        and not item.has_execute_script,
        "plugin_list_surfaces",
    )
    licensed = item.has_license
    check(licensed, "native_license_discovery")
    defaults = plugins.get_default_plugin_config("sam_mesh")
    check(defaults == plugins.get_plugin_config("sam_mesh"), "native_default_config")
    check(
        defaults["passport"]["mode"] == "explorer" and not any(defaults["features"].values()),
        "safe_explorer_defaults",
    )

    runtime = UiServerRuntime.create()
    runtime.register_http_routes()
    runtime.register_transport_handlers()
    app = runtime.webapp
    app.secret_key = uuid.uuid4().hex
    os.environ["AUTH_LOGIN"] = "sam-local-verification"
    os.environ["AUTH_PASSWORD"] = uuid.uuid4().hex
    client = app.test_client()
    check(
        client.post("/api/plugins/sam_mesh/status", json={}).status_code == 302,
        "native_authentication",
    )
    with client.session_transaction() as session:
        session["authentication"] = login.get_credentials_hash()
    check(client.post("/api/plugins/sam_mesh/status", json={}).status_code == 403, "native_csrf")
    csrf = uuid.uuid4().hex
    with client.session_transaction() as session:
        session["csrf_token"] = csrf
    headers = {"X-CSRF-Token": csrf}

    def manage(action, **data):
        response = client.post(
            "/api/plugins",
            json={"action": action, "plugin_name": "sam_mesh", **data},
            headers=headers,
        )
        assert response.status_code == 200, (action, response.status_code)
        value = response.get_json()
        assert value["ok"], action
        return value

    license_document = manage("get_doc", doc="license")
    check(
        license_document["filename"] == "LICENSE"
        and license_document["content"] == (installed / "LICENSE").read_text()
        and license_document["content"].startswith("MIT License\n"),
        "native_license_document",
    )

    for asset in (
        "webui/main.html",
        "webui/config.html",
        "webui/observatory.html",
        "webui/settings-store.js",
        "webui/observatory-store.js",
        "webui/logo.png",
        "webui/thumbnail.webp",
    ):
        check(client.get("/plugins/sam_mesh/" + asset).status_code == 200, "native_asset:" + asset)

    # The same management actions used by pluginSettingsPrototype, with actual
    # global / profile / project / project+profile files and inherited fallbacks.
    scopes = [
        ("", "", 1),
        ("", "sam-verification", 2),
        ("sam-verification", "", 3),
        ("sam-verification", "sam-verification", 4),
    ]
    for project, profile, limit in scopes:
        config = json.loads(json.dumps(defaults))
        config["passport"]["limits"]["calls_per_session"] = limit
        manage("save_config", settings=config, project_name=project, agent_profile=profile)
    for project, profile, expected in scopes + [("sam-verification", "another-profile", 3)]:
        loaded = manage("get_config", project_name=project, agent_profile=profile)
        check(
            loaded["data"]["passport"]["limits"]["calls_per_session"] == expected,
            f"native_config_scope:{project or 'global'}:{profile or 'all'}",
        )
    invalid = json.loads(json.dumps(defaults))
    invalid["transport"]["token"] = "forbidden-config-value"
    response = client.post(
        "/api/plugins",
        json={"action": "save_config", "plugin_name": "sam_mesh", "settings": invalid},
        headers=headers,
    )
    check(response.status_code >= 400, "native_config_rejects_raw_token")
    check(
        manage("get_config")["data"]["passport"]["limits"]["calls_per_session"] == 1,
        "rejected_config_preserves_previous_settings",
    )

    context = AgentContext(
        AgentConfig(mcp_servers="{}", profile="sam-verification"), id="sam-community-verification"
    )
    context.set_data(projects.CONTEXT_DATA_KEY_PROJECT, "sam-verification")
    agent = context.agent0
    for path in sorted((installed / "tools").glob("sam_*.py")):
        tool = agent.get_tool(path.stem, None, {}, "", None)
        check(Path(type(tool).execute.__code__.co_filename) == path, "native_tool:" + path.stem)
        check(
            any(
                "sam_mesh" in path
                for path in subagents.get_paths(
                    agent, "prompts", f"agent.system.tool.{tool.name}.md"
                )
            ),
            "native_prompt:" + tool.name,
        )
    for point in ("chat_model_call_before", "util_model_call_before", "tool_execute_before"):
        check(
            any(
                str(installed) in cls.execute.__code__.co_filename
                for cls in extension._get_extension_classes(point, agent)
            ),
            "native_python_extension:" + point,
        )
    manifest = extension.get_webui_extension_manifest(agent)
    check(any("sam_mesh" in str(value) for value in manifest.values()), "native_webui_manifest")
    check(
        ProviderManager().get_provider_config("chat", "sam_mesh") is not None,
        "native_provider_merge",
    )
    check(
        any("sam_mesh" in path for path in subagents.get_paths(agent, "skills", "sam-mesh")),
        "native_skill_discovery",
    )

    # Disable only this project/profile. Global activation remains independent.
    manage(
        "toggle_plugin",
        enabled=False,
        project_name="sam-verification",
        agent_profile="sam-verification",
    )
    check(
        "sam_mesh" not in plugins.get_enabled_plugins(agent)
        and "sam_mesh" in plugins.get_enabled_plugins(None),
        "independent_scoped_disable",
    )
    check(
        type(agent.get_tool("sam_mesh_status", None, {}, "", None)).__name__ == "Unknown",
        "disabled_tool_removed",
    )
    check(
        "sam_mesh" not in json.dumps(extension.get_webui_extension_manifest(agent)),
        "disabled_canvas_removed",
    )
    check(
        not any(
            str(installed) in cls.execute.__code__.co_filename
            for cls in extension._get_extension_classes("chat_model_call_before", agent)
        ),
        "disabled_inference_hook_removed",
    )
    response = client.post(
        "/api/plugins/sam_mesh/status", json={"context_id": context.id}, headers=headers
    )
    check(response.json["error_code"] == "plugin_disabled", "disabled_api_denied")
    manage(
        "toggle_plugin",
        enabled=True,
        project_name="sam-verification",
        agent_profile="sam-verification",
    )
    check("sam_mesh" in plugins.get_enabled_plugins(agent), "scoped_reenable")
    response = client.post(
        "/api/plugins/sam_mesh/emergency_disconnect",
        json={"context_id": context.id},
        headers=headers,
    )
    check(
        response.status_code == 200 and response.json.get("stopped") is True,
        "native_offline_emergency_disconnect",
    )
    manage("toggle_plugin", enabled=False, clear_overrides=True)
    check("sam_mesh" not in plugins.get_enabled_plugins(None), "global_disable")
    check(
        ProviderManager().get_provider_config("chat", "sam_mesh") is None,
        "disabled_provider_removed",
    )
    manage("delete_plugin")
    check(
        plugins.find_plugin_dir("sam_mesh") is None
        and "sam_mesh" not in plugins.get_plugins_list(),
        "native_uninstall",
    )
    check(
        not plugins.find_plugin_assets(
            "", plugin_name="sam_mesh", project_name="*", agent_profile="*", only_first=False
        ),
        "scoped_assets_removed",
    )
    return {
        "native_community_checks": checks,
        "passed": len(checks),
        "root_license_present": licensed,
        "core_modified": False,
        "sam_network_tested": False,
        "installed_copy_removed": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.archive.resolve())
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(f"Native Agent Zero community checks: {result['passed']} passed")


if __name__ == "__main__":
    main()
