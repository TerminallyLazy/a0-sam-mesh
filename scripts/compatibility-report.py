#!/usr/bin/env python3
"""Print an honest local dependency/source report; never claims live SAM compatibility."""

import importlib.metadata
import json
import platform

PACKAGES = ("httpx", "httpcore", "cryptography", "jsonschema", "fastmcp", "litellm", "openai")
versions = {}
for name in PACKAGES:
    try:
        versions[name] = importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        versions[name] = None
print(
    json.dumps(
        {
            "schema": "a0.sam.compatibility/v1alpha1",
            "python": platform.python_version(),
            "dependencies": versions,
            "source_revisions": {
                "agent_zero_framework_tested": "b1cbd1f960a1a5c4482b324dcff4742aa67b7a51",
                "agent_zero_upstream_observed": "b1cbd1f960a1a5c4482b324dcff4742aa67b7a51",
                "sam_main_source_inspected": "1966b79e7c6864876fc34722e78a050f1c23938c",
                "sam_latest_main_observed": "1966b79e7c6864876fc34722e78a050f1c23938c",
                "sam_latest_release_observed": "v0.1.0-alpha.9",
            },
            "local_dependency_report_only": True,
            "runtime_certification": "Run deploy/scripts/certify-runtime.py on the deployment host",
            "release_evidence": "docs/release-readiness.md",
            "unavailable": [
                "automatic_native_mcp_registration",
                "raw_mcp",
                "a2a",
                "semantic_intent_search",
                "peer_messaging",
            ],
            "remote_annotations_verified": False,
            "remote_risk_fallback": "unknown_requires_single_use_operator_lease",
        },
        indent=2,
    )
)
