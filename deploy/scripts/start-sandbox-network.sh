#!/bin/sh
set -eu
# The exact TUN/HTTP CONNECT translator has not been certified. Do not substitute
# proxy variables or a regular Docker network and call that confinement.
/opt/venv-a0/bin/python /pack/deploy/scripts/check-capabilities.py
echo 'No certified sandbox network bootstrap is available for this build.' >&2
exit 1
