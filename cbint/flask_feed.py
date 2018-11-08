import logging
import os

from flask import Flask
from flask import jsonify, make_response
from cbint.binary_database import DetonationResult, Binary, db
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
    cbint.globals.g_statistics.number_binaries_db = len(Binary.select())
    cbint.globals.g_statistics.number_results_db = len(DetonationResult.select(DetonationResult.md5).distinct())
    return jsonify(cbint.globals.g_statistics.to_dict())


@app.route("/debug", methods=['GET'])
def basic_pages(**kwargs):
    return make_response(open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "static", "index.html")).read())


@app.route('/debug/<md5>', methods=['GET'])
def get_hash(md5):
    try:
        return_dict = {}
        try:
            bin = Binary.get(md5=md5)
        except Binary.DoesNotExist:
            bin = None
            return_dict['binary'] = None

        try:
            dr = DetonationResult.get(md5=md5)
        except Binary.DoesNotExist:
            dr = None
            return_dict['detonation_result'] = None

        return_dict['detonation_result'] = model_to_dict(dr)
        return_dict['binary'] = model_to_dict(bin)
    except:
        logger.info(traceback.format_exc())

    return jsonify(return_dict)
