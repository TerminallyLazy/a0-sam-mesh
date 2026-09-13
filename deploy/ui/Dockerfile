# Disposable/operational network initializer only; never mounted in Agent Zero.
FROM agent0ai/agent-zero@sha256:db4617788520154de9173c59b581f4f0c6ef7a6c75c01d4c2fbc689793896b10
RUN apt-get update && apt-get install -y --no-install-recommends iptables && rm -rf /var/lib/apt/lists/*
