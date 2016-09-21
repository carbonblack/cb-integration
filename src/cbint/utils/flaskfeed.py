import os
import io
import flask

import cbint.utils.json
from cbint.utils.templates import index_template, feed_template

class FlaskFeed(object):

    def __init__(self, import_name, use_wgsi_body_helper=False, template_folder=None):

        self.local_dir = os.path.dirname(os.path.realpath(__file__))
        self.app = flask.Flask(import_name)
        if use_wgsi_body_helper:
            self.app.wsgi_app = WSGICopyBody(self.app.wsgi_app)

    def run(self, host, port, debug):
        """
        runs the flask server
        """

        self.app.run(host=host, port=port, debug=debug, use_reloader=False)

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


# The FireEye device is nice enough to set Content-Type to
# application/x-www-form-urlencoded, but _not actually encode the
# post request!  this causes flask some problems as it tries to
# decode the data (and does) but in the process un-jsonifies it.
#
# this helper is here to allow raw access to the underlying request
#
# see stackoverflow.com/questions/10999990/get-raw-post-body
#
# UPDATE: This appears to be fixed as of FireEye rev 7.0.1 or 7.0.2
#
class WSGICopyBody(object):
    def __init__(self, application):
        self.application = application

    def __call__(self, environ, start_response):
        from cStringIO import StringIO
        length = environ.get('CONTENT_LENGTH', '0')
        length = 0 if length == '' else int(length)
        body = environ['wsgi.input'].read(length)
        environ['body_copy'] = body
        environ['wsgi.input'] = StringIO(body)
        app_iter = self.application(environ, self._sr_callback(start_response))
        return app_iter

    def _sr_callback(self, start_response):
        def callback(status, headers, exc_info=None):
            start_response(status, headers, exc_info)
        return callback