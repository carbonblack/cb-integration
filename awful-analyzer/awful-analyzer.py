import os
from flask import Flask, flash, request, redirect, url_for, jsonify
import hashlib
from threading import Thread
import uuid
import random
import time

UPLOAD_FOLDER = './uploads'
SCAN_TASKS_FOLDER = './scan_tasks'

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

pending_jobs = list()


def secret_scan(md5, job_id):
    time.sleep(random.randint(1,3))
    with open(os.path.join(SCAN_TASKS_FOLDER, str(job_id)), 'w') as fp:
        fp.write(str(random.randint(0, 10)))


def get_md5(data):
    return hashlib.md5(data).hexdigest()


@app.route('/upload_sample', methods=['POST'])
def upload_sample():
    if 'sample' not in request.files:
        return jsonify({'error': 'sample not in request.files'})
    file = request.files['sample']
    if file:
        md5 = get_md5(file.read())
        file.seek(0)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], md5))
        job_id = str(uuid.uuid4())
        thread = Thread(target=secret_scan, args=(md5, job_id))
        thread.start()

        pending_jobs.append(job_id)
        return jsonify({'success': 'Everything worked', 'error': '', 'job_id': job_id})


@app.route('/get_result/<job_id>', methods=['GET'])
def get_result(job_id):
    try:
        with open(os.path.join(SCAN_TASKS_FOLDER, job_id), 'r') as fp:
            return jsonify({'result': int(fp.read().strip())})
    except Exception as e:
        #
        # check if pending
        #
        if job_id in pending_jobs:
            return jsonify({'error': 'pending'})
        else:
            return jsonify({'error': str(e)})


def main():
    app.run(host='0.0.0.0')


if __name__ == "__main__":
    main()
