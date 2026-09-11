"""Private SQLite and canonical-JSON primitives for SAM Mesh state."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .domain import Scope

BUSY_TIMEOUT_MS = 2_500
ZERO_HASH = "0" * 64
_MAX_JSON_DEPTH = 32
_MAX_JSON_NODES = 20_000
_MAX_STRING_BYTES = 1_048_576


class StorageUnavailableError(RuntimeError):
    """A sanitized fail-closed storage boundary error."""


def utc_now() -> datetime:
    return datetime.now(UTC)


def validate_clock_value(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise TypeError("clock must return a timezone-aware datetime")
    return value.astimezone(UTC)


def timestamp_us(value: datetime) -> int:
    delta = validate_clock_value(value) - datetime(1970, 1, 1, tzinfo=UTC)
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def timestamp_text(value: datetime) -> str:
    return validate_clock_value(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def parse_timestamp(value: object) -> datetime:
    """Accept only canonical UTC microsecond timestamps, without float rounding."""
    if type(value) is not str or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z", value
    ):
        raise ValueError("invalid timestamp")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if timestamp_text(parsed) != value:
        raise ValueError("invalid timestamp")
    return parsed


def validate_scope(scope: object) -> Scope:
    if not isinstance(scope, Scope):
        raise TypeError("scope must be a Scope")
    values = (scope.project_name, scope.agent_profile, scope.chat_id)
    for index, value in enumerate(values):
        if (
            type(value) is not str
            or (index == 2 and not value)
            or len(value.encode("utf-8")) > 512
            or "\x00" in value
            or any(ord(character) < 32 for character in value)
        ):
            raise ValueError("scope contains an invalid component")
    for value in (scope.project_name, scope.agent_profile):
        if value in {".", ".."} or Path(value).name != value:
            raise ValueError("scope contains an invalid path component")
    return scope


def _copy_json(value: Any, path: str, depth: int, budget: list[int]) -> Any:
    budget[0] += 1
    if budget[0] > _MAX_JSON_NODES or depth > _MAX_JSON_DEPTH:
        raise TypeError("JSON value exceeds the safe structural limit")
    if type(value) is dict:
        copied: dict[str, Any] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise TypeError(f"{path} contains a non-string JSON key")
            if len(key.encode("utf-8", errors="strict")) > _MAX_STRING_BYTES:
                raise TypeError(f"{path} contains an oversized JSON key")
            copied[key] = _copy_json(item, f"{path}.{key}", depth + 1, budget)
        return copied
    if type(value) is list:
        return [_copy_json(item, f"{path}[]", depth + 1, budget) for item in value]
    if value is None or type(value) in {bool, int}:
        return value
    if type(value) is float:
        if value != value or value in {float("inf"), float("-inf")}:
            raise TypeError(f"{path} contains a non-finite JSON number")
        return value
    if type(value) is str:
        if len(value.encode("utf-8", errors="strict")) > _MAX_STRING_BYTES:
            raise TypeError(f"{path} contains an oversized JSON string")
        return value
    raise TypeError(f"{path} must contain only plain finite JSON values")


def copy_plain_json(value: Any, path: str = "value") -> Any:
    """Defensively copy bounded, plain, finite JSON and reject custom containers."""
    return _copy_json(value, path, 0, [0])


def canonical_json_bytes(value: Any, *, domain: str) -> bytes:
    if not isinstance(domain, str) or not domain or "\x00" in domain:
        raise ValueError("canonical JSON domain must be a nonempty string")
    copied = copy_plain_json(value)
    payload = json.dumps(
        copied,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return domain.encode("ascii") + b"\x00" + payload


def canonical_hash(value: Any, *, domain: str) -> str:
    return hashlib.sha256(canonical_json_bytes(value, domain=domain)).hexdigest()


def digest_alias(value: str | None, *, domain: str, prefix: str) -> str | None:
    if value is None:
        return None
    if type(value) is not str or not value:
        raise ValueError("audit reference must be a nonempty string or null")
    digest = hashlib.sha256(domain.encode("ascii") + b"\x00" + value.encode("utf-8")).hexdigest()
    return f"{prefix}_{digest[:24]}"


def _determine_plugin_asset_path(project: str, profile: str) -> str:
    from helpers.plugins import determine_plugin_asset_path

    return determine_plugin_asset_path("sam_mesh", project, profile, "state.sqlite3")


class SQLiteStorage:
    """Open hardened short-lived SQLite connections without retaining global state."""

    def __init__(
        self,
        *,
        db_path: str | Path | None = None,
        clock: Callable[[], datetime] = utc_now,
        trusted_root: str | Path | None = None,
    ) -> None:
        self._explicit_path = None if db_path is None else Path(db_path)
        self._clock = clock
        self._trusted_root = None if trusted_root is None else Path(trusted_root)

    def now(self) -> datetime:
        return validate_clock_value(self._clock())

    def path_for_scope(self, scope: Scope) -> Path:
        validated = validate_scope(scope)
        if self._explicit_path is not None:
            path = self._explicit_path
        else:
            path = Path(
                _determine_plugin_asset_path(
                    validated.project_name,
                    validated.agent_profile,
                )
            )
        if not path.is_absolute():
            raise StorageUnavailableError("storage_unavailable")
        return path

    def connect(self, scope: Scope) -> sqlite3.Connection:
        """Traverse from / with openat, then retain verified descriptors until close.

        Explicit paths require a caller-trusted root. Production paths use A0's user
        root. The trusted process UID/root remain outside this filesystem boundary.
        """
        descriptors = []
        connection = None
        try:
            path = self.path_for_scope(scope)
            root = self._trusted_root
            if root is None:
                if self._explicit_path is not None:
                    raise ValueError("trusted root required")
                from helpers import files

                root = Path(files.get_abs_path(files.USER_DIR))
            if not root.is_absolute() or ".." in path.parts or ".." in root.parts:
                raise ValueError("invalid root")
            path.relative_to(root)
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            parent = os.open("/", flags)
            descriptors.append(parent)
            current = Path("/")
            for part in path.parent.parts[1:]:
                current = current / part
                try:
                    child = os.open(part, flags, dir_fd=parent)
                except FileNotFoundError:
                    if not current.is_relative_to(root):
                        raise
                    try:
                        os.mkdir(part, 0o700, dir_fd=parent)
                    except FileExistsError:
                        pass
                    child = os.open(part, flags, dir_fd=parent)
                descriptors.append(child)
                metadata = os.fstat(child)
                if metadata.st_uid not in {0, os.geteuid()}:
                    raise ValueError("untrusted owner")
                if current.is_relative_to(root):
                    if metadata.st_uid != os.geteuid():
                        raise ValueError("untrusted owner")
                    # Existing intermediate framework dirs may be readable, not writable.
                    if metadata.st_mode & 0o022:
                        raise ValueError("unsafe directory")
                    if current == path.parent:
                        os.fchmod(child, 0o700)
                parent = child
            db = os.open(
                path.name,
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                0o600,
                dir_fd=parent,
            )
            descriptors.append(db)
            metadata = os.fstat(db)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
            ):
                raise ValueError("unsafe database")
            os.fchmod(db, 0o600)
            for suffix in ("-wal", "-shm", "-journal"):
                try:
                    side = os.stat(path.name + suffix, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if (
                    not stat.S_ISREG(side.st_mode)
                    or side.st_uid != os.geteuid()
                    or side.st_nlink != 1
                    or side.st_mode & 0o077
                ):
                    raise ValueError("unsafe sidecar")
            connection = sqlite3.connect(
                f"/proc/self/fd/{db}",
                timeout=BUSY_TIMEOUT_MS / 1000,
                isolation_level=None,
                factory=_AnchoredConnection,
            )
            # SQLite resolves the proc fd to the verified inode's current pathname.
            opened = connection.execute("PRAGMA database_list").fetchone()[2]
            actual = os.stat(opened, follow_symlinks=False)
            if (actual.st_dev, actual.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise ValueError("database substituted")
            connection.row_factory = sqlite3.Row
            connection.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA synchronous = FULL")
            if connection.execute("PRAGMA journal_mode = WAL").fetchone()[0] != "wal":
                raise ValueError("WAL unavailable")
            connection._descriptors = descriptors
            descriptors = []
            return connection
        except (OSError, ValueError, ImportError, sqlite3.Error):
            if connection is not None:
                connection.close()
            raise StorageUnavailableError("storage_unavailable") from None
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)


class _AnchoredConnection(sqlite3.Connection):
    """Own Linux directory/inode anchors for exactly the connection lifetime."""

    def close(self):
        try:
            super().close()
        finally:
            for descriptor in reversed(getattr(self, "_descriptors", [])):
                os.close(descriptor)
            self._descriptors = []
