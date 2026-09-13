"""Immutable, explicitly bounded inbound service definitions."""

import re
from dataclasses import dataclass, fields

_NAME = re.compile(r"^[a-z][a-z0-9-]{2,62}$")
_SCOPE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
BROKER_TOOLS = ("service_info", "ask_specialist", "finish_session")
HTTP_CONTRACT_MARKER = "SAM Embassy HTTP v1: "


@dataclass(frozen=True)
class EmbassyService:
    name: str
    project: str
    agent_profile: str
    description: str = "Bounded Agent Zero specialist"
    type: str = "mcp"
    persistence: str = "stateless"
    max_runtime_seconds: int = 300
    max_input_bytes: int = 262144
    max_attachment_bytes: int = 0
    max_concurrency: int = 2
    requests_per_minute: int = 6
    idle_expiry_seconds: int = 900
    agent_tool_policy: tuple[str, ...] = ("response",)

    def __post_init__(self):
        if type(self.name) is not str or not _NAME.fullmatch(self.name):
            raise ValueError("invalid_service_name")
        for value in (self.project, self.agent_profile):
            if type(value) is not str or not _SCOPE.fullmatch(value) or ".." in value:
                raise ValueError("invalid_service_scope")
        if self.type != "mcp" or self.persistence not in {"stateless", "isolated_chat"}:
            raise ValueError("unsupported_service_contract")
        if type(self.description) is not str or len(self.description.encode()) > 2048:
            raise ValueError("invalid_service_description")
        if type(self.max_attachment_bytes) is not int or self.max_attachment_bytes != 0:
            raise ValueError("attachments_are_disabled")
        for key, maximum in (
            ("max_runtime_seconds", 900),
            ("max_input_bytes", 1048576),
            ("max_concurrency", 8),
            ("requests_per_minute", 60),
            ("idle_expiry_seconds", 3600),
        ):
            value = getattr(self, key)
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError("invalid_service_limit")
        if (
            type(self.agent_tool_policy) is not tuple
            or not self.agent_tool_policy
            or self.agent_tool_policy != ("response",)
        ):
            raise ValueError("unsupported_agent_tool_policy")

    @classmethod
    def from_dict(cls, value):
        if type(value) is not dict or value.keys() - {f.name for f in fields(cls)}:
            raise ValueError("unknown_service_field")
        raw = dict(value)
        if "agent_tool_policy" in raw:
            if not isinstance(raw["agent_tool_policy"], (tuple, list)):
                raise ValueError("invalid_agent_tool_policy")
            raw["agent_tool_policy"] = tuple(raw["agent_tool_policy"])
        try:
            return cls(**raw)
        except TypeError:
            raise ValueError("service_name_project_and_profile_required") from None
