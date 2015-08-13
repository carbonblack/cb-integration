import logging

from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from threading import Thread, Event

try:
    import simplejson as json
except ImportError:
    import json

logging.getLogger("requests").setLevel(logging.WARNING)


class MockServer(object):
    def __init__(self, port, handler_class):
        self.stop_event = Event()
        self.port = port
        self.handler_class = handler_class
        self.server_thread = None

    def start(self):
        self.server_thread = Thread(target=self._start, args=(self.port, self.handler_class, self.stop_event))
        self.server_thread.setDaemon(True)
        self.server_thread.start()

    def stop(self):
        self.stop_event.set()

    @staticmethod
    def _start(port, handler_class, stop_event):
        httpd = HTTPServer(('127.0.0.1', port), handler_class)
        while not stop_event.is_set():
            try:
                httpd.handle_request()
            except Exception, e:
                print "Server Request Failed: %s" % e


class MockServerHandler(BaseHTTPRequestHandler):
    """
    Base mock server handler class to be overridden for testing purposes
    Add methods of the form "do_<HTTP_METHOD>(self)" to handle HTTP actions

        e.g.

        def do_GET(self):
            try:
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"status": "success"}))
            except:
                pass

    """
    def log_message(self, fmt, *args):
        """
        Override to suppress log messages in output
        """
        pass

    def finish(self, *args, **kwargs):
        """
        Override finish to handle a python bug: http://bugs.python.org/issue14574
        """
        try:
            if not self.wfile.closed:
                self.wfile.flush()
                self.wfile.close()
        except:
            pass
        self.rfile.close()


def get_carbon_black_handler(root_directory):
    class SubHandler(MockCarbonBlackServer):
        requests = []
        server_root = root_directory

    return SubHandler


class MockCarbonBlackServer(MockServerHandler):
    def do_GET(self):
        return self.cb_mock_response('GET')

    def do_POST(self):
        return self.cb_mock_response('POST')

    def cb_mock_response(self, method):
        self.requests.append((method, self.path))
        try:
            if self.path.find("/api/v1/process") >= 0:
                data_string = self.rfile.read(int(self.headers['Content-Length']))
                data = json.loads(data_string)
                start = 0 if "start" not in data else int(data["start"][0])
                cluster_response = {}
                cluster_response["status"] = "success"
                response = json.dumps(cluster_response)
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', len(response))
                self.end_headers()
                self.wfile.write(response)
                return
        except Exception, e:
            print "POST ERROR::: %s" % e
