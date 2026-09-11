"""Reviewable native MCP plans; safe modes cannot expose a generic gateway."""

from .capabilities import EXPECTED_READ_TOOL_SCHEMAS


def build_native_mcp_plan(config, compatibility):
    enabled = sorted(set(compatibility.enabled_tools) & set(EXPECTED_READ_TOOL_SCHEMAS))
    observed = {t.wire_name for t in compatibility.observed_tools}
    disabled = sorted(
        (observed - set(enabled))
        | {
            "call_remote_tool",
            "get_recent_logs",
            "get_network_info",
            "send_message",
            "mesh_pubsub_broadcast",
            "poll_messages",
            "subscribe_topic",
        }
    )
    reason = None
    if config.transport.type != "http":
        reason = "native_mcp_has_no_uds_transport"
    elif config.transport.token:
        reason = "native_mcp_secret_reference_unavailable"
    else:
        # Disabled-tool lists do not deny unknown tools added after a refresh.
        # Require host Tool Access default-deny before using a native gateway.
        reason = "native_tool_access_allowlist_required"
    return {
        "available": False,
        "reason": reason,
        "applied": False,
        "transport": "streamable_http",
        "enabled_tools": enabled,
        "disabled_tools": disabled,
        "proposal": {
            "sam_mesh": {
                "type": "streamable-http",
                "url": config.transport.base_url.rstrip("/") + "/mcp",
                "headers": {},
                "disabled_tools": disabled,
            }
        },
        "guidance": "Use the governed plugin tools. Native registration requires an operator "
        "review of Tool Access and credential handling; no settings were applied.",
    }
