import errno
import os
import sys
from contextlib import contextmanager
from cbfeeds import CbFeed, CbFeedInfo
from tempfile import NamedTemporaryFile
import logging
from logging.handlers import RotatingFileHandler
import time

class AlreadyRunningError(Exception):
    pass


# TODO: investigate psutil package instead (https://pypi.python.org/pypi/psutil)
def pid_exists(pid):
    """Check whether pid exists in the current process table.
    UNIX only.
    """
    if pid < 0:
        return False
    if pid == 0:
        # According to "man 2 kill" PID 0 refers to every process
        # in the process group of the calling process.
        # On certain systems 0 is a valid PID but we have no way
        # to know that in a portable fashion.
        raise ValueError('invalid PID 0')
    try:
        os.kill(pid, 0)
    except OSError as err:
        if err.errno == errno.ESRCH:
            # ESRCH == No such process
            return False
        elif err.errno == errno.EPERM:
            # EPERM clearly means there's a process to deny access to
            return True
        else:
            # According to "man 2 kill" possible error values are
            # (EINVAL, EPERM, ESRCH)
            raise
    else:
        return True

@contextmanager
def file_lock(lock_file):
    if os.path.exists(lock_file):
        try:
            pid = int(file(lock_file).read())
            if pid_exists(pid):
                print 'Only one instance can run at once. ' \
                      'Script is locked with %s (pid: %s)' % (lock_file, pid)
                raise AlreadyRunningError('PID %s' % pid)
        except:
            pass

    open(lock_file, 'w').write("%d" % os.getpid())
    try:
        yield
    finally:
        os.remove(lock_file)


class CbIntegrationBridge(object):
    """Create a Carbon Black integration bridge that's run on a periodic basis.

    Integrations should derive a subclass from CbIntegrationBridge if they
    intend to periodically update a threat intelligence feed on the Carbon Black server.

    Integrations that use this class are intended to run on the Carbon Black server itself.

    Subclasses of this Bridge class must implement the following methods:
    * perform
    * integration_display_name
    * integration_summary
    * integration_detail
    * integration_url
    * integration_icon

    The run function should return a list of CbReports (from cbfeeds) that will be placed into
    the

    Subclasses should use the self.logger attribute to log errors & info messages as necessary.
    """

    WORKING_FILE_ROOT = '/var/run/cb'
    LOG_FILE_ROOT = '/var/log/cb/integrations'
    CONFIGURATION_ROOT = '/etc/cb/integrations'

    def __init__(self, integration_name, debug=False):
        self.integration_name = integration_name
        self.debug = debug

        self._initialize_logging()
        self.feed_metadata = self._initialize_feed()
        self.working_file_root = os.path.join(CbIntegrationBridge.WORKING_FILE_ROOT, integration_name)
        self.feed_file_name = os.path.join(self.working_file_root, '%s.json' % self.integration_name)

    def _initialize_logging(self):
        logging_file_path = os.path.join(CbIntegrationBridge.LOG_FILE_ROOT, '%s.log' % self.integration_name)

        self.logger = logging.getLogger(self.integration_name)
        self.logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        formatter.converter = time.gmtime
        handler = RotatingFileHandler(logging_file_path, maxBytes=2**20, backupCount=10)
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        if self.debug:
            self.logger.setLevel(logging.DEBUG)
            handler = logging.StreamHandler(sys.stderr)
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def _initialize_feed(self):
        feed = {"name": self.integration_name, "display_name": self.integration_display_name(),
                "summary": self.integration_summary(), "tech_data": self.integration_detail(),
                "provider_url": self.integration_url(), "icon": self.integration_icon() }

        return CbFeedInfo(**feed)

    def run(self):
        try:
            with file_lock(os.path.join(CbIntegrationBridge.WORKING_FILE_ROOT, '%s.pid' % self.integration_name)):
                reports = self.perform()

                if not reports:
                    return True

                if self.debug:
                    self.print_reports(reports)

                # Create the feed
                feed = CbFeed(self.feed_metadata, reports)
                if not feed.validate():
                    self.logger.error("Feed {0:s} did not validate, not updating".format(self.integration_name))
                    return False

                raw_feed_data = feed.dump()

                with NamedTemporaryFile(dir=self.working_file_root, delete=False) as fp:
                    fp.write(raw_feed_data)
                    self.logger.info("Creating {0:s} feed at {1:s}".format(self.integration_name, self.feed_file_name))
                    os.rename(fp.name, self.feed_file_name)

                c = connect_local_cbapi()
                feed_id = c.feed_get_id_by_name(self.integration_name)
                if not feed_id:
                    self.logger.info("Creating {0:s} feed for the first time".format(self.integration_name))
                    c.feed_add_from_url("file://" + self.feed_file_name, True, False, False)

                # force a synchronization
                c.feed_synchronize(self.integration_name)
        except AlreadyRunningError:
            self.logger.error("{0:s} is already running".format(self.integration_name))

    @staticmethod
    def print_reports(reports):
        for report in reports:
            print 'report {0:s} (id {1:s} link {2:s}):'.format(report['title'], report['id'], report['link'])
            for indicator_type in report['iocs']:
                for indicator_value in report['iocs'][indicator_type]:
                    print indicator_type, indicator_value

    def integration_description(self):
        return ""

    def integration_icon(self):
        return ""

    def integration_display_name(self):
        return self.integration_name

    def integration_summary(self):
        return self.integration_name

    def integration_detail(self):
        return ""

    def integration_url(self):
        return ""

    def perform(self):
        return None