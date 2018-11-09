import logging
import os

from flask import Flask
from flask import jsonify, make_response
from cbint.binary_database import BinaryDetonationResult
import json
from playhouse.shortcuts import model_to_dict
import traceback

import cbint.globals

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

app = Flask('cbint', static_folder=os.path.join(os.path.dirname(os.path.realpath(__file__)), "static"))


@app.route("/debug/force_rescan_all", methods=['POST'])
def rescan():
    cbint.globals.g_integration.force_rescan_all()
    return jsonify({'success': True})


@app.route("/debug/stats", methods=['GET'])
def statistics():
    cbint.globals.g_statistics.number_binaries_db = len(BinaryDetonationResult.select())
    return jsonify(cbint.globals.g_statistics.to_dict())


@app.route("/debug", methods=['GET'])
def basic_pages(**kwargs):
    return make_response(open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "static", "index.html")).read())


@app.route('/debug/<md5>', methods=['GET'])
def get_hash(md5):
    return_dict = {}
    try:
        try:
            bdr = BinaryDetonationResult.get(md5=md5)
        except BinaryDetonationResult.DoesNotExist:
            bdr = None
            return_dict['binary_detonation_result'] = None

        return_dict['binary_detonation_result'] = model_to_dict(bdr)

    except:
        except_msg = traceback.format_exc()
        logger.info(except_msg)
        return_dict['error_msg'] = except_msg

    return jsonify(return_dict)
