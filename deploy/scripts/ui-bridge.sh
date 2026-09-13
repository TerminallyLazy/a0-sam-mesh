#!/bin/sh
set -eu
exec /opt/venv-a0/bin/python /pack/deploy/scripts/ui-bridge.py sandbox --port="${A0_WEBUI_PORT:-80}"
