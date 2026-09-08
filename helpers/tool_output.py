"""Bounded untrusted text-only history boundary; never dereference media or URLs."""
import json
import re

from .domain import DataClass
from .sam_client import _plain_json

_SECRET = re.compile(r'(?i)token|secret|password|authorization|cookie|credential')


def safe_output(value, *, token=None):
    """Bounded recursive key redaction and exact node-credential removal."""
    def clean(item):
        if isinstance(item, dict):
            return {key: '[redacted]' if _SECRET.search(key) else clean(val)
                    for key, val in item.items()}
        if isinstance(item, list):
            return [clean(val) for val in item]
        if isinstance(item, str):
            return item.replace(token, '[redacted]') if token else item
        return item
    result = clean(_plain_json(value))
    rendered = json.dumps(result, allow_nan=False)
    if len(rendered.encode()) > 16384:
        return {'error_code': 'output_too_large', 'untrusted': True}
    return result


def inspect_result(result, arguments, token, data_class):
    if data_class is not DataClass.PUBLIC:
        return ({'type': 'text', 'text': '[sensitive result withheld from model history]'},)
    content = []
    for part in result.content:
        if part.get('type') != 'text' or not isinstance(part.get('text'), str):
            continue
        text = part['text']
        # JSON text gets the same key-based redaction as structured data.
        try:
            text = json.dumps(safe_output(json.loads(text), token=token))
        except (ValueError, TypeError):
            if token:
                text = text.replace(token, '[redacted]')
        content.append({'type': 'text', 'text': text})
    bounded = safe_output(content, token=token)
    if isinstance(bounded, dict):
        return ({'type': 'text', 'text': '[output_too_large]'},)
    return tuple(bounded)
