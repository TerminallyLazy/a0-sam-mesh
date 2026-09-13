#!/bin/sh
set -eu
# This owns a fresh, dedicated Docker network namespace. No user/agent namespace
# or Docker control socket is accessible. Install both families before readiness.
for restore in iptables-restore ip6tables-restore; do
  "$restore" <<'RULES'
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]
-A INPUT -p tcp --dport 8080 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -p tcp --sport 8080 -m conntrack --ctstate ESTABLISHED -j ACCEPT
COMMIT
RULES
done
# No process serving UI runs until the firewall is ready. The lifetime keeper
# relinquishes even the initializer capabilities and cannot alter these rules.
touch /run/firewall-ready
exec capsh --drop=all -- -c 'exec sleep infinity'
