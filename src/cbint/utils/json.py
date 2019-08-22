

try:
    import simplejson as json
except ImportError:
    from . import json

def json_encode(data):
    """
    generic json encoding logic
    uses cjson if available; json if not
    """
    return json.dumps(data)


def json_decode(data):
    """
    generic json decoding logic
    uses cjson if available; json if not
    """
    return json.loads(data)