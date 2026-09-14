"""Native installation, managed-node lifetime, and safe settings boundaries."""

from usr.plugins.sam_mesh.helpers.config import validate_storage_config


def get_plugin_config(default=None, **kwargs):
    return validate_storage_config(default)


def ensure_runtime(settings=None, retry=False, **kwargs):
    from usr.plugins.sam_mesh.helpers.managed_node import manager

    from helpers import plugins

    if settings is None:
        settings = plugins.get_plugin_config("sam_mesh")
    settings = validate_storage_config(settings)
    if (
        settings.get("connection", "external") != "managed"
        or settings["passport"]["mode"] == "sovereign"
    ):
        return {"status": "external"}
    return manager().ensure(retry=retry)


def managed_transport():
    from usr.plugins.sam_mesh.helpers.managed_node import manager

    return manager().transport()


def save_plugin_config(settings=None, **kwargs):
    normalized = validate_storage_config(settings)
    ensure_runtime(normalized, retry=True)
    return normalized


def install(**kwargs):
    return ensure_runtime(retry=True)


def stop_runtime(**kwargs):
    from usr.plugins.sam_mesh.helpers import embassy_runtime
    from usr.plugins.sam_mesh.helpers.decisions import invalidate_pending_decisions
    from usr.plugins.sam_mesh.helpers.managed_node import manager

    invalidate_pending_decisions()
    if embassy_runtime._runtime is not None:
        embassy_runtime._runtime.shutdown()
    return manager().stop()


def pre_update(**kwargs):
    return stop_runtime()


def uninstall(**kwargs):
    return stop_runtime()
