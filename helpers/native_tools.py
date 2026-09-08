"""Exact model schemas and bounded dispatch, independent of framework imports."""
import json
from jsonschema import Draft202012Validator

from .storage import copy_plain_json


def _schema(properties=None, required=()):
    return dict(type='object', properties=properties or {}, required=list(required),
                additionalProperties=False)


_TEXT = dict(type='string', minLength=1, maxLength=512)
_IDENTITY = dict(peer_id=_TEXT, tool_name=dict(type='string', pattern=r'^mcp://[^/]+/.+',
                                             maxLength=1024))
SCHEMAS = {
    'sam_mesh_status': _schema(),
    'sam_list_local_services': _schema({'type': {'enum': ['mcp', 'inference']}}),
    'sam_discover_services': _schema({
        'type': {'enum': ['mcp', 'inference']}, 'name': _TEXT,
        'limit': dict(type='integer', minimum=1, maximum=100),
        'offset': dict(type='integer', minimum=0, maximum=10000)}, ('type',)),
    'sam_find_tools': _schema({'peer_id': _TEXT, 'service_name': _TEXT, 'tool_name': _TEXT}),
    'sam_describe_tool': _schema(_IDENTITY, ('peer_id', 'tool_name')),
    'sam_preflight_tool': _schema({**_IDENTITY, 'arguments': {'type': 'object'},
        'data_class': {'enum': ['public', 'internal', 'confidential', 'regulated']}},
        ('peer_id', 'tool_name', 'arguments', 'data_class')),
    'sam_call_remote_tool': _schema({'decision_id': dict(type='string', minLength=20,
                                                       maxLength=128)}, ('decision_id',)),
    'sam_list_models': _schema(),
    'sam_route_preview': _schema(_IDENTITY, ('peer_id', 'tool_name')),
}


def validate_arguments(name, value):
    try:
        value = copy_plain_json(value)
        if len(json.dumps(value).encode()) > 16384:
            raise ValueError()
        Draft202012Validator(SCHEMAS[name]).validate(value)
        return value
    except Exception:
        raise ValueError('invalid_tool_arguments') from None
