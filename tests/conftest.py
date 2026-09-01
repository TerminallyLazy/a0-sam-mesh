import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import pytest


PLUGIN_ROOT = Path(__file__).resolve().parents[1]


def _pin_plugin_link(path: Path) -> int:
    """Open a non-following descriptor that pins a staged symlink inode."""
    return os.open(path, os.O_PATH | os.O_NOFOLLOW)


def _resolve_a0_checkout() -> Path:
    """Resolve the explicit Agent Zero checkout configured for integration tests."""
    configured = os.environ.get("A0_CHECKOUT", "").strip()
    if not configured:
        raise RuntimeError("A0_CHECKOUT must point to an Agent Zero checkout")

    checkout = Path(configured).expanduser().resolve()
    if not (checkout / "helpers" / "plugins.py").is_file():
        raise RuntimeError(f"A0_CHECKOUT is not an Agent Zero checkout: {checkout}")
    return checkout


@contextmanager
def _install_plugin(checkout: Path) -> Iterator[Path]:
    """Install this repository for a checkout and remove only the link created here."""
    plugins_dir = checkout / "usr" / "plugins"
    plugins_dir.mkdir(parents=True, exist_ok=True)
    plugin_link = plugins_dir / "sam_mesh"

    owned_link_fd: int | None = None
    published = False
    try:
        with tempfile.TemporaryDirectory(
            prefix=".sam_mesh-install-", dir=plugins_dir
        ) as staging_dir:
            staged_link = Path(staging_dir) / "sam_mesh"
            staged_link.symlink_to(PLUGIN_ROOT, target_is_directory=True)
            owned_link_fd = _pin_plugin_link(staged_link)
            try:
                os.link(staged_link, plugin_link, follow_symlinks=False)
            except FileExistsError as exc:
                raise RuntimeError(
                    f"Refusing to replace existing plugin path: {plugin_link}"
                ) from exc
            published = True

        yield checkout
    finally:
        if owned_link_fd is not None:
            try:
                if published:
                    try:
                        current_link = plugin_link.lstat()
                    except FileNotFoundError:
                        pass
                    else:
                        owned_link = os.fstat(owned_link_fd)
                        if (
                            plugin_link.is_symlink()
                            and current_link.st_dev == owned_link.st_dev
                            and current_link.st_ino == owned_link.st_ino
                        ):
                            plugin_link.unlink()
            finally:
                os.close(owned_link_fd)


@pytest.fixture(scope="session")
def a0_checkout() -> Iterator[Path]:
    """Yield an Agent Zero checkout with this repository installed as sam_mesh."""
    with _install_plugin(_resolve_a0_checkout()) as checkout:
        yield checkout


@pytest.fixture(scope="session")
def installed_plugin(a0_checkout: Path) -> Path:
    """Compatibility alias for tests that explicitly request an installed plugin."""
    return a0_checkout / "usr" / "plugins" / "sam_mesh"
