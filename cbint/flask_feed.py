import logging
import os

from flask import Flask
from flask import jsonify, make_response

import cbint.globals

logger = logging.getLogger(__name__)

app = Flask('cbint', static_folder=os.path.join(os.path.dirname(os.path.realpath(__file__)), "static"))


@app.route("/stats", methods=['GET'])
def statistics():
    return jsonify(cbint.globals.g_statistics.to_dict())


@app.route("/", methods=['GET'])
def basic_pages(**kwargs):
    return make_response(open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "static", "index.html")).read())
