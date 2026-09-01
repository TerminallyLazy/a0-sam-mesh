import os
from pathlib import Path

import pytest


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
AUDITED_A0_CHECKOUT = Path("/a0/usr/projects/sam_a0_plugin")


@pytest.fixture(scope="session")
def a0_checkout() -> Path:
    """Return the explicit Agent Zero checkout used by integration tests."""
    checkout = Path(os.environ.get("A0_CHECKOUT", AUDITED_A0_CHECKOUT)).expanduser().resolve()
    if not (checkout / "helpers" / "plugins.py").is_file():
        raise RuntimeError(f"A0_CHECKOUT is not an Agent Zero checkout: {checkout}")
    return checkout


@pytest.fixture
def installed_plugin(a0_checkout: Path):
    """Install this repository as sam_mesh and remove only the link created here."""
    plugins_dir = a0_checkout / "usr" / "plugins"
    plugins_dir.mkdir(parents=True, exist_ok=True)
    plugin_link = plugins_dir / "sam_mesh"

    try:
        plugin_link.symlink_to(PLUGIN_ROOT, target_is_directory=True)
    except FileExistsError as exc:
        raise RuntimeError(f"Refusing to replace existing plugin path: {plugin_link}") from exc

    owned_link = plugin_link.lstat()
    try:
        yield plugin_link
    finally:
        try:
            current_link = plugin_link.lstat()
        except FileNotFoundError:
            return
        if (
            plugin_link.is_symlink()
            and current_link.st_dev == owned_link.st_dev
            and current_link.st_ino == owned_link.st_ino
        ):
            plugin_link.unlink()
