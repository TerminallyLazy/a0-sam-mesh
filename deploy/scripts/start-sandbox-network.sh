#!/bin/sh
set -eu
# Published nano-init performs namespace, boundary, TUN and routing checks itself.
# Do not remove/ignore interfaces to make a failing host appear certified.
if [ "$#" -eq 0 ]; then
  set -- /opt/venv-a0/bin/python /a0/run_ui.py --host=127.0.0.1 --port="${A0_WEBUI_PORT:-80}"
fi
exec /opt/sam/nano-init run /run/sam-agent/agent.sock \
  /opt/venv-a0/bin/python /pack/deploy/scripts/start-agent.py "$@"
