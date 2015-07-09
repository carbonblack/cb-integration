#
# Adapted from http://www.jejik.com/articles/2007/02/a_simple_unix_linux_daemon_in_python/
#

import os
import sys
import time
import atexit
import logging
import ConfigParser
from logging.handlers import RotatingFileHandler
from signal import SIGTERM

import cbint.utils.filesystem


class CbIntegrationDaemon(object):
    """
    A generic daemon class.

    Usage: subclass the Daemon class and override the run() method
    """

    def __init__(self, name, configfile=None, logfile=None, pidfile=None,
                 stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
        self.name = name
        self.configfile = configfile
        self.logfile = logfile
        self.pidfile = pidfile
        self.options = {}
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.__is_initialized = False
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.INFO)

        euid = os.geteuid()
        if euid != 0:
            sys.stderr.write("%s: must be root to run (try sudo?)\n" % self.name)
            sys.exit(1)

        self.__initialize_common()

    def daemonize(self):
        """
        do the UNIX double-fork magic, see Stevens' "Advanced
        Programming in the UNIX Environment" for details (ISBN 0201563177)
        http://www.erlenstar.demon.co.uk/unix/faq_2.html#SEC16
        """

        try:
            pid = os.fork()
            if pid > 0:
                # exit first parent
                sys.exit(0)
        except OSError, e:
            sys.stderr.write("%s: fork #1 failed: %d (%s)\n" % (self.name, e.errno, e.strerror))
            sys.exit(1)

        # decouple from parent environment
        os.chdir("/")
        os.setsid()
        os.umask(0)

        # do second fork
        try:
            pid = os.fork()
            if pid > 0:
                # exit from second parent
                sys.exit(0)
        except OSError, e:
            sys.stderr.write("%s: fork #2 failed: %d (%s)\n" % (self.name, e.errno, e.strerror))
            sys.exit(1)

        # redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        si = file(self.stdin, 'r')
        so = file(self.stdout, 'a+')
        se = file(self.stderr, 'a+', 0)
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

        # write pidfile
        atexit.register(self.delpid)
        pid = str(os.getpid())
        file(self.pidfile, 'w+').write("%s\n" % pid)

    def delpid(self):
        os.remove(self.pidfile)

    def start(self):
        """
        Start the daemon
        """
        self.on_starting()

        # Check for a pidfile to see if the daemon already runs
        try:
            pf = file(self.pidfile, 'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            pid = None

        if pid:
            sys.stderr.write("%s: pidfile %s already exist. Daemon already running?\n" % (self.name, self.pidfile))
            sys.exit(1)

        self.logger.info("daemon starting...")

        if not self.validate_config():
            error_msg = "config file validation failed: %s" % self.configfile or "None"
            sys.stderr.write("%s: error: %s\n" % (self.name, error_msg))
            self.logger.error(error_msg)
            sys.exit(1)

        # Start the daemon
        self.daemonize()
        try:
            self.run()
        except Exception as e:
            self.logger.critical("an exception occurred while running the daemon: %s" % e)

        self.logger.info("the daemon has stopped")

        self.on_start()

        sys.exit(1)

    def stop(self):
        """
        Stop the daemon
        """
        self.on_stopping()

        # Get the pid from the pidfile
        try:
            pf = file(self.pidfile, 'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            pid = None

        if not pid:
            sys.stderr.write("%s: pidfile %s does not exist. Daemon not running?\n" % (self.name, self.pidfile))
            # not an error in a restart
            return

        self.logger.info("daemon stopping...")

        # Try killing the daemon process
        try:
            while 1:
                os.kill(pid, SIGTERM)
                time.sleep(0.1)
        except OSError, err:
            err = str(err)
            if err.find("No such process") > 0:
                if os.path.exists(self.pidfile):
                    os.remove(self.pidfile)
            else:
                print str(err)
                sys.exit(1)

        self.on_stop()

    def restart(self):
        """
        Restart the daemon
        """
        self.stop()
        self.start()

    def run(self):
        """
        You should override this method when you subclass. It will be called after the process has been
        daemonized by start() or restart().
        """

    def on_starting(self):
        """
        You should override this method when you subclass if you want to take action BEFORE the service is starting
        """

    def on_start(self):
        """
        You should override this method when you subclass if you want to take action AFTER the service has started
        """

    def on_stopping(self):
        """
        You should override this method when you subclass if you want to take action BEFORE the service is stopping
        """

    def on_stop(self):
        """
        You should override this method when you subclass if you want to take action AFTER the service has stopped
        """

    def validate_config(self):
        """
        You should override this method when you subclass.  Use it to validate the configuration contained
        in self.options and return true if the configuration is acceptable, otherwise false.
        """
        return True

    def __parse_config(self, configfile):
        """
        Parses the config file to set the app options
        """

        if not os.path.exists(configfile):
            warning_msg = "could not locate config file: %s" % configfile or "None"
            sys.stderr.write("%s: warning: %s\n" % (self.name, warning_msg))
            self.logger.warn(warning_msg)
            return

        self.logger.info("parsing configuration")
        cfg = ConfigParser.ConfigParser()
        cfg.read(configfile)
        for section in cfg.sections():
            self.options[section] = {}
            self.logger.info("section: %s" % section)
            for option in cfg.options(section):
                self.options[section][option] = cfg.get(section, option)
                self.logger.info("   %s: %s" % (option, cfg.get(section, option)))

    def __initialize_common(self):
        """
        Initialized common variables and objects that are needed by start and stop
        """

        if not self.__is_initialized:
            if self.pidfile is None:
                pid_path = "/var/run/cb/integrations/"
                cbint.utils.filesystem.ensure_directory_exists(pid_path)
                self.pidfile = "%s%s.pid" % (pid_path, self.name)

            if self.logfile is None:
                log_path = "/var/log/cb/integrations/%s/" % self.name
                cbint.utils.filesystem.ensure_directory_exists(log_path)
                self.logfile = "%s%s.log" % (log_path, self.name)

            if self.configfile is None:
                config_path = "/etc/cb/integrations/%s/" % self.name
                cbint.utils.filesystem.ensure_directory_exists(config_path)
                self.configfile = "%s%s.cfg" % (config_path, self.name)

            rlh = RotatingFileHandler(self.logfile, maxBytes=524288, backupCount=10)
            rlh.setFormatter(logging.Formatter(fmt="%(asctime)s: %(module)s: %(levelname)s: %(message)s"))
            self.logger.addHandler(rlh)

            self.__parse_config(self.configfile)

            self.__is_initialized = True
