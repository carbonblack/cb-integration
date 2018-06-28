from flask import Flask

import logging
import cbint.globals

from flask import jsonify

logger = logging.getLogger(__name__)

app = Flask('cbint')


@app.route("/stats", methods=['GET'])
def statistics():
    return jsonify(cbint.globals.g_statistics.to_dict())
