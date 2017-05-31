import Queue
import os, sqlite3
import re
from time import sleep
import threading
import datetime
import flask
import traceback

try:
    import simplejson as json
except ImportError:
    import json
import copy
import logging
from cbint.utils.templates import binary_template
import dateutil.parser

epoch = datetime.datetime(1970, 1, 1)
log = logging.getLogger(__name__)

notification_queue = Queue.Queue(maxsize=10)


class BinaryDatabaseArbiter(object):
    def __init__(self, binary_queue, subscriber_id, notification_source, queue):
        self.binary_queue = binary_queue
        self.subscriber_id = subscriber_id
        self.notification_source = notification_source
        self.result_queue = queue

    def binaries(self):
        while True:
            notification_queue.put(self.subscriber_id)
            md5sum = self.result_queue.get()
            log.debug("database_arbiter returning md5sum %s to subscriber %d" % (md5sum, self.subscriber_id))
            yield md5sum
            self.result_queue.task_done()

    def notify_binary_available(self, md5sum):
        self.binary_queue.append(md5sum)
        notification_queue.put(self.subscriber_id)

    def mark_as_analyzed(self, *args, **kwargs):
        self.binary_queue.mark_as_analyzed(*args, **kwargs)

    def mark_quick_scan_complete(self, *args, **kwargs):
        self.binary_queue.mark_quick_scan_complete(*args, **kwargs)

    def get_value(self, *args, **kwargs):
        return self.binary_queue.get_value(*args, **kwargs)

    def set_value(self, *args, **kwargs):
        return self.binary_queue.set_value(*args, **kwargs)


class BinaryDatabaseController(threading.Thread):
    def __init__(self, binary_queue):
        super(BinaryDatabaseController, self).__init__()
        self.binary_queue = binary_queue
        self.subscribers = []
        self.subscriber_id = 0
        self.waiting = []
        self.binaries_available = True
        self.last_binary_check = datetime.datetime.utcnow()
        self.timeout_period = datetime.timedelta(minutes=1)

    def register(self, notification_source, quick_scan=False):
        this_subscriber = self.subscriber_id
        queue = Queue.Queue()
        self.subscribers.append({"queue": queue, "notification_source": notification_source,
                                 "quick_scan": quick_scan})
        self.subscriber_id += 1

        log.debug("Registered notification source %s - got id %d" % (notification_source, this_subscriber))

        return BinaryDatabaseArbiter(self.binary_queue, this_subscriber, notification_source, queue)

    def return_binary(self, subscriber_id):
        subscriber = self.subscribers[subscriber_id]
        md5sum = self.binary_queue.get(sleep_wait=False, quick_scan=subscriber["quick_scan"])
        if not md5sum:
            log.debug("return_binary: No binary available, setting binaries_available to false")
            self.waiting.insert(0, subscriber_id)
            self.binaries_available = False
            return None
        else:
            log.debug("return_binary: Binary returned: %s" % md5sum)
            return md5sum

    def run(self):
        try:
            while True:
                if datetime.datetime.utcnow() - self.last_binary_check > self.timeout_period:
                    # every minute or so, just see if there are binaries available in the database anyway
                    log.debug("Binary timeout period elapsed; forcing database check")
                    self.binaries_available = True
                    self.last_binary_check = datetime.datetime.utcnow()

                if self.waiting and self.binaries_available:
                    subscriber_id = self.waiting.pop()
                    md5sum = self.return_binary(subscriber_id)
                    if md5sum:
                        self.subscribers[subscriber_id]["queue"].put(md5sum)
                        self.last_binary_check = datetime.datetime.utcnow()
                        continue

                try:
                    subscriber_id = notification_queue.get(timeout=1)
                except Queue.Empty:
                    log.debug("Notification Queue empty, returning to top")
                    continue
                except Exception:
                    log.info(traceback.format_exc())
                    continue

                notification_queue.task_done()

                try:
                    subscriber_id = int(subscriber_id)
                    subscriber = self.subscribers[subscriber_id]
                    if subscriber["notification_source"] == "producer":
                        # notifying that we have a new binary available
                        self.binaries_available = True
                        self.last_binary_check = datetime.datetime.utcnow()
                    elif subscriber["notification_source"] == "consumer":
                        log.debug("Consumer %d waiting for binary" % subscriber_id)
                        self.waiting.insert(0, subscriber_id)
                except Exception:
                    log.info(traceback.format_exc())
                    continue
        except:
            log.info(traceback.format_exc())


class SqliteQueue(object):
    _create_queue = '''CREATE TABLE IF NOT EXISTS binary_data (
  md5sum                 VARCHAR(32) PRIMARY KEY NOT NULL,
  -- timestamps
  last_modified          DATETIME,
  inserted_at            DATETIME,
  next_attempt_at        DATETIME,
  binary_available_since DATETIME,
  quick_scan_done        BOOLEAN,
  retry_count            INTEGER,
  -- results
  short_result           TEXT,            -- this can be an error if the state is an error state
  detailed_result        TEXT,            -- we convert to HTML before storing in here
  score                  INTEGER,
  iocs                   TEXT,            -- this is just a dump of JSON data
  provider_data          TEXT,            -- this is arbitrary data from the provider
  link                   TEXT,
  -- state
  state                  INTEGER,         -- define states below
  analysis_version       INTEGER
);
'''
    _create_metadata = '''CREATE TABLE IF NOT EXISTS feed_data (
  -- versioning
  database_version INTEGER,
  feed_version     INTEGER,
  analysis_version INTEGER                 -- the current "analysis" version. we can re-analyze things in the background
);
'''
    _create_kvstore = '''CREATE TABLE IF NOT EXISTS kv_store (
  -- arbitrary key-value store for configuration information
  key              TEXT,
  value            TEXT
);
'''
    _append = (
        'INSERT INTO binary_data (md5sum, last_modified, inserted_at, state, quick_scan_done, retry_count) '
        'VALUES (?, ?, ?, 0, 0, 0)'
    )
    _write_lock = 'BEGIN IMMEDIATE'
    _popleft_get = (
        'SELECT * FROM binary_data WHERE (state = 0 OR ((julianday(?) - julianday(last_modified)) > ?) ) '
        'AND (next_attempt_at < ? OR next_attempt_at IS NULL) '
        'AND retry_count < ? '
        'ORDER BY binary_available_since DESC,next_attempt_at ASC LIMIT 1'
    )
    _quickscan_get = (
        'SELECT md5sum FROM binary_data WHERE ( ( state = 0 AND quick_scan_done = 0 ) '
        'OR ((julianday(?) - julianday(last_modified)) > ?) ) '
        'AND retry_count < ? LIMIT 1'
    )
    _update_queue = 'UPDATE binary_data SET state=50,last_modified = ? WHERE md5sum = ?'
    _all_analyzed = 'SELECT * FROM binary_data WHERE state = 100'
    _update_binary_availability = ('UPDATE binary_data SET last_modified = ?,binary_available_since = ?,'
                                   'next_attempt_at = NULL WHERE md5sum = ?')
    _update_binary_state = ('UPDATE binary_data SET last_modified = ?,next_attempt_at = ?,short_result = ?,'
                            'detailed_result = ?,score = ?,state = ?,analysis_version = ?,link = ?,iocs = ? '
                            'WHERE md5sum = ?')
    _reprocess_binaries_on_restart = 'UPDATE binary_data SET state = 0 WHERE state = 50'
    _add_iocs = 'UPDATE binary_data SET iocs = ? WHERE md5sum = ?'
    _set_metadata = 'INSERT INTO feed_data (database_version) VALUES (?)'
    _count_by_state = 'SELECT COUNT(*) FROM binary_data WHERE state = ?'
    _quick_scan_complete = "UPDATE binary_data SET quick_scan_done=1, state=0 WHERE md5sum = ?"

    _current_db_version = 7

    def __init__(self, path, max_retry_count=10, num_days_before_rescan=365):
        self.path = os.path.abspath(path)
        self._connection_cache = {}
        self.max_retry_count = max_retry_count
        self.num_days_before_rescan = num_days_before_rescan

        with self._get_conn() as conn:
            conn.execute(self._create_queue)
            conn.execute(self._create_metadata)
            conn.execute(self._create_kvstore)

            cur = conn.cursor()
            cur.execute("SELECT database_version FROM feed_data")
            res = cur.fetchone()
            if not res:
                # we've never used this database before, set the database version information
                cur.execute(self._set_metadata, (self._current_db_version,))
            else:
                (version,) = res
                if version != self._current_db_version:
                    self.migrate_version(version)

    def _get_conn(self):
        id = threading.current_thread().ident
        if id not in self._connection_cache:
            self._connection_cache[id] = sqlite3.Connection(self.path,
                                                            timeout=60)
            self._connection_cache[id].row_factory = sqlite3.Row
        return self._connection_cache[id]

    def number_unanalyzed(self):
        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute(self._count_by_state, (0,))
            (count,) = cur.fetchone()

        return count

    def append(self, md5sum, file_available=False):
        # returns True if a new item was created, False otherwise
        now = datetime.datetime.utcnow()
        with self._get_conn() as conn:
            try:
                conn.execute(self._append, (md5sum, now, now))
            except sqlite3.IntegrityError:
                conn.commit()  # unlock the database
                created = False
            else:
                created = True

            if file_available:
                self.set_binary_available(md5sum, now)

        return created

    def set_binary_available(self, md5sum, as_of=None):
        now = datetime.datetime.utcnow()
        if not as_of:
            as_of = now
        with self._get_conn() as conn:
            conn.execute(self._update_binary_availability, (now, as_of, md5sum))

    def add_iocs(self, md5sum, iocs):
        ioc_string = json.dumps(iocs)
        with self._get_conn() as conn:
            conn.execute(self._add_iocs, (ioc_string, md5sum))

    def mark_as_analyzed(self, md5sum, succeeded, analysis_version, short_result, long_result, score=0, retry_at=None,
                         link=None, iocs=None):
        # print 'marking as analyzed: %s as %s: version %s, results: %s/%s, score: %d. retry? %s' % (
        #     md5sum, succeeded, analysis_version, short_result, long_result, score, retry_at
        # )
        if not succeeded:
            # mark state as an error state. if we never want to retry, it's permanent.
            if not retry_at:
                state = -100
            else:
                state = 0
        else:
            state = 100

        if not retry_at:
            retry_at = ''

        # print "%s analyzing %s with score %d" % ("Success" if succeeded else "Failed", md5sum, score)
        # if not succeeded:
        #     print datetime.datetime.utcnow(), retry_at, short_result, long_result, score, state, analysis_version, md5sum

        with self._get_conn() as conn:
            if not succeeded:
                cur = conn.cursor()
                cur.execute("SELECT retry_count FROM binary_data WHERE md5sum=?", (md5sum,))
                (current_retry_count,) = cur.fetchone()
                conn.execute("UPDATE binary_data SET retry_count=? WHERE md5sum=?", (current_retry_count + 1, md5sum))
            else:
                conn.execute("UPDATE binary_data SET retry_count=0 WHERE md5sum=?", (md5sum,))
            conn.execute(self._update_binary_state, (datetime.datetime.utcnow(), str(retry_at), str(short_result),
                                                     str(long_result), int(score), state, analysis_version,
                                                     link, iocs, md5sum))

    def binary_exists_in_database(self, md5sum):
        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM binary_data WHERE md5sum=?", (md5sum,))
            results = cur.fetchone()
            if not results:
                return False
            else:
                return True

    def mark_quick_scan_complete(self, md5sum):
        with self._get_conn() as conn:
            conn.execute(self._quick_scan_complete, (md5sum,))

    def get(self, quick_scan=False, sleep_wait=True):
        keep_pooling = True
        wait = 0.1
        max_wait = 2
        tries = 0
        with self._get_conn() as conn:
            while keep_pooling:
                conn.execute(self._write_lock)
                if quick_scan:
                    cursor = conn.execute(self._quickscan_get,
                                          (datetime.datetime.utcnow(), self.num_days_before_rescan,
                                           self.max_retry_count))
                else:
                    cursor = conn.execute(self._popleft_get,
                                          (datetime.datetime.utcnow(), self.num_days_before_rescan,
                                           datetime.datetime.utcnow(), self.max_retry_count))
                try:
                    results = cursor.next()
                    md5sum = results['md5sum']
                    keep_pooling = False
                except StopIteration:
                    conn.commit()  # unlock the database
                    if not sleep_wait:
                        keep_pooling = False
                        continue
                    tries += 1
                    sleep(wait)
                    wait = min(max_wait, tries / 10 + wait)
                except Exception:
                    log.info(traceback.format_exc())
                    conn.commit()
                else:
                    conn.execute(self._update_queue, (datetime.datetime.utcnow(), md5sum))
                    conn.commit()
                    return md5sum
        return None

    def reprocess_on_restart(self):
        with self._get_conn() as conn:
            conn.execute(self._reprocess_binaries_on_restart)

    def migrate_version(self, old_version):
        with self._get_conn() as conn:
            if old_version < 3:
                conn.execute("ALTER TABLE binary_data ADD COLUMN quick_scan_done BOOLEAN")
                conn.execute("UPDATE binary_data SET quick_scan_done=0")
                conn.execute("UPDATE feed_data SET database_version=3")

            if old_version < 4:
                conn.execute("ALTER TABLE binary_data ADD COLUMN retry_count INTEGER")
                conn.execute("UPDATE binary_data SET retry_count=0")
                conn.execute("UPDATE feed_data SET database_version=4")

            if old_version < 5:
                conn.execute("ALTER TABLE binary_data ADD COLUMN provider_data TEXT")
                conn.execute("UPDATE feed_data SET database_version=5")

            if old_version < 6:
                conn.execute("ALTER TABLE binary_data ADD COLUMN link TEXT")
                conn.execute("UPDATE feed_data SET database_version=6")

            if old_version < 7:
                computed_time_difference = datetime.datetime.utcnow() - datetime.datetime.now()
                computed_hours = round(computed_time_difference.total_seconds() / 3600, 1)

                log.info("Attempting to migrate timestamps from old database from localtime to GMT")
                log.info(
                    "This conversion is approximate and will shift timestamps stored in the database by %f hours" % computed_hours)
                log.info("")
                log.info("if there are errors, re-initialize the database by removing the file")
                log.info(self.path)
                log.info("and restart the service")

                self._migrate_timestamps(conn, computed_time_difference)
                conn.execute("UPDATE feed_data SET database_version=7")

    def _migrate_timestamps(self, conn, time_shift):
        rows = list(conn.execute(
            "SELECT md5sum,last_modified,inserted_at,next_attempt_at,binary_available_since FROM binary_data"))
        for row in rows:
            new_timestamp = []
            for i in range(1, 5):
                dt = None
                if row[i] is not None:
                    try:
                        dt = dateutil.parser.parse(row[i])
                        dt += time_shift
                    except Exception as e:
                        log.exception("Could not convert %s to date/time stamp for md5sum %s" % (row[i], row[0]))

                new_timestamp.append(dt)
            conn.execute(
                "UPDATE binary_data SET last_modified = ?, inserted_at = ?, next_attempt_at = ?, binary_available_since = ? WHERE md5sum = ?",
                (new_timestamp[0], new_timestamp[1], new_timestamp[2], new_timestamp[3], row[0]))

    def get_value(self, keyname, default=None):
        with self._get_conn() as conn:
            cursor = conn.execute("SELECT value FROM kv_store WHERE key=?", (keyname,))
            results = cursor.fetchone()
            if not results:
                return default
            else:
                return results[0]

    def set_value(self, keyname, new_value):
        log.info("Updating kvstore %s to %s" % (keyname, new_value))

        with self._get_conn() as conn:
            cursor = conn.execute("SELECT value FROM kv_store WHERE key=?", (keyname,))
            if cursor.fetchone():
                conn.execute("UPDATE kv_store SET value=? WHERE key=?", (new_value, keyname))
            else:
                conn.execute("INSERT INTO kv_store VALUES (?, ?)", (keyname, new_value))


class SqliteFeedServer(threading.Thread):
    _get_feed_contents = 'SELECT * FROM binary_data'
    _get_analyzed_binaries = 'SELECT md5sum,last_modified,short_result,detailed_result,iocs,score,link FROM binary_data WHERE state=100'

    def __init__(self, dbname, port_number, feed_metadata, link_base_url, work_directory, cert_file=None, key_file=None,
                 listener_address='0.0.0.0'):
        threading.Thread.__init__(self)
        self.daemon = True
        self.dbname = dbname
        self.port_number = port_number
        self.feed_metadata = feed_metadata
        self.listener_address = listener_address
        self.link_base_url = link_base_url
        self.work_directory = work_directory

        self.cert_file = cert_file
        self.key_file = key_file

        self.app = flask.Flask(__name__)
        self.app.debug = False

        self.app.add_url_rule("/binaries.html", view_func=self.binary_results, methods=['GET'])
        self.app.add_url_rule("/feed.json", view_func=self.feed_content, methods=['GET'])
        self.app.add_url_rule("/", view_func=self.index, methods=['GET'])
        self.app.add_url_rule("/reports/<string:report_id>", view_func=self.report_results, methods=["GET"])

        self.valid_filename_regex = re.compile("^[A-Za-z0-9\-_\.]*$")

    def index(self):
        return flask.redirect("/binaries.html")

    def report_results(self, report_id):
        log.info("report_results ENTER")
        if not self.valid_filename_regex.match(report_id):
            log.critical("Attempt to retrieve invalid report file '%s'" % report_id)
            log.info("report_results: not self.valid_filename_regex.match")
            flask.abort(404)
        if "sqlite.db" in report_id:
            log.info("report_results: sqlite.db in report_id")
            flask.abort(404)
        try:
            log.info("report_results: Attempting to read file {}".format(os.path.join(self.work_directory, report_id)))
            fp = open(os.path.join(self.work_directory, report_id), 'rb')
        except IOError:
            log.info(traceback.format_exc())
            flask.abort(404)
        except Exception:
            log.info(traceback.format_exc())
            flask.abort(500)
        else:
            log.info("else/success case")
            fp.seek(0)
            return flask.send_file(fp, mimetype='application/pdf')

    def feed_content(self):
        cur = self.conn.cursor()
        cur.execute(self._get_analyzed_binaries)
        binaries = cur.fetchall()

        feed_data = copy.deepcopy(self.feed_metadata)
        feed_data['reports'] = []
        for binary in binaries:
            # Only report binaries with a non-zero score
            if int(binary[5]) > 0:
                if binary[6]:  # link present
                    if binary[6].startswith("/reports/"):
                        # a relative link. Build this at feed generation time
                        link = self.link_base_url + binary[6]
                    else:
                        # an absolute link. Pass along unchanged
                        link = binary[6]
                else:
                    link = ''

                feed_data['reports'].append({
                    'timestamp': int((dateutil.parser.parse(binary[1]) - epoch).total_seconds()),
                    'id': "Binary_%s" % binary[0],
                    'link': link,
                    'title': binary[2],
                    'score': binary[5],
                    'iocs': {  # TODO: merge iocs from the database
                        'md5': [
                            binary[0],
                        ]
                    }
                })

        return flask.Response(json.dumps(feed_data), mimetype='application/json')

    def binary_results(self):
        cur = self.conn.cursor()
        cur.execute(self._get_feed_contents)
        binaries = cur.fetchall()
        return flask.render_template_string(binary_template, binaries=binaries, integration_name='test_feed')

    def run(self):
        self.conn = sqlite3.Connection(self.dbname, timeout=60)
        self.conn.row_factory = sqlite3.Row

        try:
            if self.cert_file and self.key_file:
                context = (self.cert_file, self.key_file)
            else:
                context = None

            self.app.run(host=self.listener_address,
                         port=self.port_number,
                         ssl_context=context,
                         debug=False,
                         use_reloader=False)

        except:
            log.info(traceback.format_exc())
