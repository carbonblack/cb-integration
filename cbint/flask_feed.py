from flask import Flask

import logging
import os

from sqlite3 import dbapi2 as sqlite3
from flask import Blueprint, request, session, g, redirect, url_for, abort, \
    render_template, flash, current_app, send_from_directory

logger = logging.getLogger(__name__)


def index():
    logger.info(os.path.join(os.getcwd(), 'feed'))
    return send_from_directory(os.path.join(os.getcwd(), 'feed'), 'feed.json')


def create_flask_app():
    app = Flask('cbint')
    bp = Blueprint('response_feed', __name__)

    bp.route('/')(index)
    bp.route('/feed.json')(index)

    app.register_blueprint(bp)

    return app
