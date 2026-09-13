#!/usr/bin/env python3
"""Provision operator-owned Embassy trust without exporting or replacing its private key."""

import argparse
import base64
import os
import re
import stat
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


def directory(path):
    path = Path(path)
    if not path.is_absolute() or path.resolve() != path:
        raise ValueError("absolute_directory_without_symlinks_required")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("owner_only_directory_required")
    return path


def read_key(path):
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise ValueError("owner_only_regular_key_required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        current = os.fstat(fd)
        if (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino):
            raise ValueError("key_changed_during_validation")
        raw = os.read(fd, 129)
        if len(raw) > 128:
            raise ValueError("invalid_key")
        return raw
    finally:
        os.close(fd)


def create_key(path, raw):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _overlap(paths):
    return any(
        first == second or first in second.parents or second in first.parents
        for index, first in enumerate(paths)
        for second in paths[index + 1 :]
    )


def _mount_sources(paths):
    """Resolve Linux bind destinations to their same-filesystem backing roots."""
    if not sys.platform.startswith("linux"):
        return []
    # Linux provisioning must not claim a safe layout if its mount topology
    # cannot be inspected, including container bind mounts at unrelated paths.
    mounts = []
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        if len(fields) < 10 or "-" not in fields:
            raise ValueError("mount_topology_unavailable")

        def unescape(value):
            return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), value)

        root, target = Path(unescape(fields[3])), Path(unescape(fields[4]))
        if not root.is_absolute() or not target.is_absolute():
            raise ValueError("mount_topology_unavailable")
        mounts.append((fields[2], root, target))
    sources = []
    for path in paths:
        matching = [mount for mount in mounts if path == mount[2] or mount[2] in path.parents]
        if not matching:
            raise ValueError("mount_topology_unavailable")
        device, root, target = max(matching, key=lambda mount: len(mount[2].parts))
        sources.append((device, root / path.relative_to(target)))
    return sources


def validate_directories(paths):
    paths = tuple(map(Path, paths))
    if any(not path.is_absolute() or path.resolve() != path for path in paths):
        raise ValueError("absolute_directory_without_symlinks_required")
    if _overlap(paths):
        raise ValueError("separate_mount_directories_required")
    sources = _mount_sources(paths)
    for index, (device, path) in enumerate(sources):
        if any(
            device == other_device and _overlap([path, other])
            for other_device, other in sources[index + 1 :]
        ):
            raise ValueError("separate_mount_directories_required")
    return paths


def provision(private_dir, public_dir, socket_dir):
    paths = validate_directories((private_dir, public_dir, socket_dir))
    private_dir, public_dir, socket_dir = map(directory, paths)
    private, public = private_dir / "private.key", public_dir / "public.key"
    if private.exists() or private.is_symlink():
        key = Ed25519PrivateKey.from_private_bytes(
            base64.b64decode(read_key(private), validate=True)
        )
    else:
        if public.exists() or public.is_symlink():
            raise ValueError("existing_public_identity_requires_its_private_key")
        key = Ed25519PrivateKey.generate()
        create_key(
            private,
            base64.b64encode(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())),
        )
    expected = base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    if public.exists() or public.is_symlink():
        if read_key(public) != expected:
            raise ValueError("public_key_does_not_match_private_identity")
    else:
        create_key(public, expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-dir", required=True)
    parser.add_argument("--public-dir", required=True)
    parser.add_argument("--socket-dir", required=True)
    args = parser.parse_args()
    try:
        provision(args.private_dir, args.public_dir, args.socket_dir)
    except (ValueError, OSError):
        parser.exit(
            1,
            "Embassy provisioning refused: check separate owner-only directories and matching key files.\n",
        )
    print(
        "Embassy identity ready. Mount only the public directory and broker socket in Agent Zero."
    )


if __name__ == "__main__":
    main()
