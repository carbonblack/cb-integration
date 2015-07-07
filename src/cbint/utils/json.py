from __future__ import absolute_import

import json


def json_encode(data):
    """
    generic json encoding logic
    uses cjson if available; json if not
    """
    try:
        import cjson
        return cjson.encode(data)
    except Exception, e:
        return json.dumps(data)


def json_decode(data):
    """
    generic json decoding logic
    uses cjson if available; json if not
    """
    try:
        import cjson
        return cjson.decode(data)
    except Exception, e:
        return json.loads(data)