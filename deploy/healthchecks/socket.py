"""Check owner-only socket admission without issuing a SAM request."""

import os
import socket
import stat
import sys

path = sys.argv[1]
st = os.stat(path)
if not stat.S_ISSOCK(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
    raise SystemExit(1)
with socket.socket(socket.AF_UNIX) as client:
    client.settimeout(2)
    client.connect(path)
