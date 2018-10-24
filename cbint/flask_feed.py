import logging
import os

from flask import Flask
from flask import jsonify, make_response
from cbint.binary_database import BinaryDetonationResult, db

import cbint.globals

logger = logging.getLogger(__name__)
'''
app = Flask('cbint', static_folder=os.path.join(os.path.dirname(os.path.realpath(__file__)), "static"))


@app.route("/force_rescan_all", methods=['POST'])
def rescan():
    cbint.globals.g_integration.force_rescan_all()
    return jsonify({'success': True})


@app.route("/stats", methods=['GET'])
def statistics():
    cbint.globals.g_statistics.number_binaries_db = len(BinaryDetonationResult.select())
    return jsonify(cbint.globals.g_statistics.to_dict())


@app.route("/", methods=['GET'])
def basic_pages(**kwargs):
    return make_response(open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "static", "index.html")).read())

'''





