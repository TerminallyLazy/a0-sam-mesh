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
                "sam_main_source_inspected": "787374aa823d289a2aa15ee1791973f438cb295d",
                "sam_latest_main_observed": "077a43e2e89e544bc6ecfbf6b4607706490592ad",
                "sam_latest_release_observed": "v0.1.0-alpha.9",
            },
            "live_sam_verified": False,
            "sovereign_network_verified": False,
            "unavailable": [
                "automatic_native_mcp_registration",
                "raw_mcp",
                "a2a",
                "semantic_intent_search",
                "peer_messaging",
                "embassy_publication",
                "sovereign_startup",
            ],
            "remote_annotations_verified": False,
            "remote_risk_fallback": "unknown_requires_single_use_operator_lease",
        },
        indent=2,
    )
)
