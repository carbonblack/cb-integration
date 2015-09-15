import logging
import os

try:
    import simplejson as json
except ImportError:
    import json

from flask import Flask, request, make_response, Response
from cStringIO import StringIO
import zipfile
import re
import dateutil.parser


log = logging.getLogger(__name__)


def get_mocked_server(binary_directory):
    mocked_cb_server = Flask('cb')

    files = os.listdir(binary_directory)
    binaries = [json.load(open(os.path.join(binary_directory, fn), 'r')) for fn in files]
    filter_re = re.compile("server_added_timestamp:\[(.*) TO (.*)\]")

    @mocked_cb_server.route('/api/v1/binary', methods=['GET', 'POST'])
    def binary_search_endpoint():
        if request.method == 'GET':
            query_string = request.args.get('q', '')
            sort_string = request.args.get('sort', 'server_added_timestamp desc')
            rows = int(request.args.get('rows', 10))
            start = int(request.args.get('start', 0))
        elif request.method == 'POST':
            parsed_data = json.loads(request.data)
            if 'q' in parsed_data:
                query_string = parsed_data['q']
            else:
                query_string = ''

            if 'rows' in parsed_data:
                rows = int(parsed_data['rows'])
            else:
                rows = 10

            if 'start' in parsed_data:
                start = int(parsed_data['start'])
            else:
                start = 0

            if 'sort' in parsed_data:
                sort_string = parsed_data['sort']
            else:
                sort_string = 'server_added_timestamp desc'

        else:
            return make_response('Invalid Request', 500)

        if type(query_string) == list:
            query_string = query_string[0]

        return Response(response=json.dumps(binary_search(query_string, rows, start, sort_string)),
                        mimetype='application/json')

    def binary_search(q, rows, start, sort_string):
        # we only support 'q' on server_added_timestamp
        log.info("typeof(q) = %s" % q.__class__.__name__)
        matches = filter_re.search(q)
        if not matches:
            filtered_binaries = binaries
        else:
            if matches.group(1) == '*':
                limit = dateutil.parser.parse(matches.group(2))
                filtered_binaries = filter(lambda x: dateutil.parser.parse(x['server_added_timestamp']) <= limit,
                                           binaries)
            else:
                limit = dateutil.parser.parse(matches.group(1))
                filtered_binaries = filter(lambda x: dateutil.parser.parse(x['server_added_timestamp']) > limit,
                                           binaries)

        (field, direction) = sort_string.split()
        if direction == 'asc':
            reverse = False
        else:
            reverse = True

        sorted_binaries = sorted(filtered_binaries, key=lambda x: x[field], reverse=reverse)[start:start+rows]

        return {
            'results': sorted_binaries,
            'terms': '',
            'total_results': len(sorted_binaries),
            'start': start,
            'elapsed': 0.1,
            'highlights': [],
            'facets': {}
        }

    @mocked_cb_server.route('/api/v1/binary/<md5sum>/summary')
    def get_binary_summary(md5sum):
        filepath = os.path.join(binary_directory, '%s.json' % md5sum.lower())
        if not os.path.exists(filepath):
            return Response("File not found", 404)

        binary_data = open(filepath, 'r').read()
        return Response(response=binary_data, mimetype='application/json')

    @mocked_cb_server.route('/api/v1/binary/<md5sum>')
    def get_binary(md5sum):
        filepath = os.path.join(binary_directory, '%s.json' % md5sum.lower())
        if not os.path.exists(filepath):
            return Response("File not found", 404)

        md5sum = md5sum.lower()
        sample_data = 'PE. This file is a mocked PE binary with md5sum %s' % md5sum
        zipfile_contents = StringIO()
        zf = zipfile.ZipFile(zipfile_contents, 'w', zipfile.ZIP_DEFLATED, False)
        zf.writestr('filedata', sample_data)
        zf.writestr('metadata', open(filepath, 'r').read())
        zf.close()

        return Response(response=zipfile_contents.getvalue(), mimetype='application/zip')

    @mocked_cb_server.route('/api/info')
    def info():
        return Response(response=json.dumps({"version": "5.1.0"}), mimetype='application/json')

    return mocked_cb_server


if __name__ == '__main__':
    mydir = os.path.dirname(os.path.abspath(__file__))
    binaries_dir = os.path.join(mydir, '..', 'data', 'binary_metadata')

    mock_server = get_mocked_server(binaries_dir)
    mock_server.run('127.0.0.1', 7982, debug=True)
