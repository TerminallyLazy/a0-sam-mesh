"""Linux inode-pinned UDS connects; validated at each actual pool connection."""

import os
import stat

import httpcore
import httpx
from httpcore._backends.anyio import AnyIOBackend

from .config import _validate_socket_metadata


class PinnedUnixBackend(AnyIOBackend):
    async def connect_unix_socket(self, path, timeout=None, socket_options=None):
        descriptors = []
        try:
            if not os.path.isabs(path) or ".." in path.split("/"):
                raise ValueError("invalid_socket_path")
            parent = os.open("/", os.O_PATH | os.O_DIRECTORY)
            descriptors.append(parent)
            parts = path.split("/")[1:]
            for part in parts[:-1]:
                parent = os.open(part, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                descriptors.append(parent)
                metadata = os.fstat(parent)
                # Sticky /tmp permits private test roots but not socket substitution therein.
                if metadata.st_uid not in {0, os.geteuid()}:
                    raise ValueError("unsafe_socket_parent")
                if metadata.st_mode & 0o022 and not metadata.st_mode & stat.S_ISVTX:
                    raise ValueError("unsafe_socket_parent")
            fd = os.open(parts[-1], os.O_PATH | os.O_NOFOLLOW, dir_fd=parent)
            descriptors.append(fd)
            _validate_socket_metadata(os.fstat(fd))
            return await super().connect_unix_socket(f"/proc/self/fd/{fd}", timeout, socket_options)
        except Exception:
            raise httpcore.ConnectError("uds_validation_failed") from None
        finally:
            for fd in reversed(descriptors):
                os.close(fd)


class PinnedUnixTransport(httpx.AsyncHTTPTransport):
    def __init__(self, path):
        # HTTPX adapter handles core exception mapping; a dedicated public core pool
        # supplies the verified backend. No network pool created by super is used.
        self._pool = httpcore.AsyncConnectionPool(
            uds=path,
            retries=0,
            network_backend=PinnedUnixBackend(),
            max_connections=4,
            max_keepalive_connections=0,
        )
