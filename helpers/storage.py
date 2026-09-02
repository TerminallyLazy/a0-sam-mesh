"""Private SQLite and canonical-JSON primitives for SAM Mesh state."""

from __future__ import annotations

import hashlib
import json
import os
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
    return int(validate_clock_value(value).timestamp() * 1_000_000)


def timestamp_text(value: datetime) -> str:
    return validate_clock_value(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def validate_scope(scope: object) -> Scope:
    if not isinstance(scope, Scope):
        raise TypeError("scope must be a Scope")
    values = (scope.project_name, scope.agent_profile, scope.chat_id)
    for value in values:
        if (
            type(value) is not str
            or not value
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
        return [
            _copy_json(item, f"{path}[]", depth + 1, budget)
            for item in value
        ]
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
    ) -> None:
        self._explicit_path = None if db_path is None else Path(db_path)
        self._clock = clock

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

    def _prepare_path(self, path: Path) -> None:
        try:
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            parent = path.parent.lstat()
            if stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode):
                raise StorageUnavailableError("storage_unavailable")
            os.chmod(path.parent, 0o700)
            try:
                metadata = path.lstat()
            except FileNotFoundError:
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                try:
                    descriptor = os.open(path, flags, 0o600)
                except FileExistsError:
                    metadata = path.lstat()
                else:
                    os.close(descriptor)
                    metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise StorageUnavailableError("storage_unavailable")
            if metadata.st_uid != os.geteuid():
                raise StorageUnavailableError("storage_unavailable")
            os.chmod(path, 0o600)
        except StorageUnavailableError:
            raise
        except (OSError, ValueError) as exc:
            raise StorageUnavailableError("storage_unavailable") from exc

    def connect(self, scope: Scope) -> sqlite3.Connection:
        path = self.path_for_scope(scope)
        self._prepare_path(path)
        try:
            connection = sqlite3.connect(
                path,
                timeout=BUSY_TIMEOUT_MS / 1_000,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA synchronous = FULL")
            journal = connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            if str(journal).casefold() != "wal":
                connection.close()
                raise StorageUnavailableError("storage_unavailable")
            os.chmod(path, 0o600)
            return connection
        except StorageUnavailableError:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise StorageUnavailableError("storage_unavailable") from exc
