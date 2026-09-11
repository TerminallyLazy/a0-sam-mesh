"""Guard Agent Zero's generic config storage and config-response boundary."""

from usr.plugins.sam_mesh.helpers.config import validate_storage_config


def save_plugin_config(settings=None, **kwargs):
    return validate_storage_config(settings)


def get_plugin_config(default=None, **kwargs):
    return validate_storage_config(default)
