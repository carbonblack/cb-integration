import os
import io
import flask
import logging

import cbint.utils.json
from cbint.utils.templates import index_template, feed_template

logger = logging.getLogger(__name__)

class FlaskFeed(object):

    def __init__(self, import_name, cert_file=None, key_file=None, template_folder=None):

        self.local_dir = os.path.dirname(os.path.realpath(__file__))
        self.app = flask.Flask(import_name)

        self.cert_file = cert_file
        self.key_file = key_file

    def run(self, host, port, debug=False):
        """
        runs the flask server
        """

        if self.cert_file and self.key_file:
            context = (self.cert_file, self.key_file)
        else:
            context = None

        self.app.run(host=host, port=port, ssl_context=context, debug=False, use_reloader=False)

    def generate_json_feed(self, feed):
        """
        generates the feed in json format
        """

        return flask.Response(response=cbint.utils.json.json_encode(feed), mimetype='application/json')

    def generate_html_feed(self, feed, integration_name):
        """
        generates the feed in html format
        """

        return flask.render_template_string(feed_template, feed=feed, integration_name=integration_name)

    def generate_html_index(self, feed, options, integration_name,
                            cb_image_path, integration_image_path, json_feed_path, last_sync=None):
        """
        generated the html index page for the feed
        """

        # make a copy of the feed object
        # this is for two reasons:
        #  (1) remove the icon from the feedinfo dictionary
        #      the icon is excessively long in base64 format and does not render
        #      'properly' in index.html
        #  (2) add the num_reports field.  this is here for convenience
        #      programmatically, it can be achieved by len(feed['reports']), but
        #      that doesn't lend itself to human consumption
        #
        feed_copy = {}
        feed_copy['reports'] = feed['reports']
        feed_copy['feedinfo'] = {}
        for key in feed['feedinfo']:
            if key != 'icon':
                feed_copy['feedinfo'][key] = feed['feedinfo'][key]
        feed_copy['feedinfo']['num_reports'] = len(feed['reports'])

        options_copy = {}
        for key in options:
            if key == "carbonblack_server_token":
                continue
            elif key == "listener_api_token":
                continue
            else:
                options_copy[key] = options[key]

        return flask.render_template_string(index_template, options=options_copy, feed=feed_copy,
                                     integration_name=integration_name, integration_image_path=integration_image_path,
                                     cb_image_path=cb_image_path, json_feed_path=json_feed_path, last_sync=last_sync)

    def generate_image_response(self, image_bytes=None, image_path=None):
        """
        generates a result containing an image
        """
        if image_bytes:
            return flask.send_file(io.BytesIO(image_bytes))
        else:
            try:
                f = open(image_path, "rb")
                return flask.send_file(io.BytesIO(f.read()))
            except:
                flask.abort(404)