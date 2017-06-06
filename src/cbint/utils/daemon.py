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
import errno
import traceback
import cbint.utils.filesystem
from netifaces import interfaces, ifaddresses, AF_INET6, AF_INET, gateways

log = logging.getLogger(__name__)

class Timer(object):
    def __enter__(self):
        self.start = time.time()
        return self

    def __exit__(self, *args):
        self.end = time.time()
        self.interval = self.end - self.start


class ConfigurationError(Exception):
    pass


class CbIntegrationDaemon(object):
    """
    A generic daemon class.

    Usage: subclass the Daemon class and override the run() method
    """

    def __init__(self, name, configfile=None, logfile=None, pidfile=None,
                 stdin='/dev/null', stdout='/dev/null', stderr='/dev/null',
                 debug=False):
        self.name = name
        self.configfile = configfile
        self.cfg = None
        self.logfile = logfile
        self.pidfile = pidfile
        self.options = {}
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.__is_daemon_initialized = False
        self.__is_logging_initialized = False

        self.debug = debug

        # Disable requests verbose logging at INFO level
        logging.getLogger("requests").setLevel(logging.WARNING)

        if self.configfile is None:
            config_path = "/etc/cb/integrations/%s/" % self.name
            cbint.utils.filesystem.ensure_directory_exists(config_path)
            self.configfile = "%s%s.cfg" % (config_path, self.name)

        self.__initialize_logging()

        try:
            self.__parse_config(self.configfile)
        except Exception as e:
            self.fatal(e)

        if self.debug:                            # set in __parse_config
            log.setLevel(logging.DEBUG)
        else:
            euid = os.geteuid()
            if euid != 0:
                sys.stderr.write("%s: must be root to run (try sudo?)\n" % self.name)
                sys.exit(1)

            self.__initialize_daemon()

    def fatal(self, e):
        # log the Exception everywhere
        msg = "%s (%s)" % (e.message, e.__class__.__name__)
        sys.stderr.write("%s: %s\n" % (self.name, msg))
        sys.stderr.flush()
        log.critical(msg)
        log.critical("Traceback: %s" % traceback.format_exc())
        sys.exit(1)

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
        try:
            os.remove(self.pidfile)
        except OSError as e:
            if e.errno != errno.ENOENT:
                raise

    def start(self):
        """
        Start the daemon
        """
        if not self.debug:
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

        log.info("daemon starting...")

        try:
            # for backwards compatibility, validate_config() can also return False
            if not self.validate_config():
                raise ConfigurationError("Configuration file validation failed for %s" % self.configfile)
        except Exception as e:
            self.fatal(e)

        ssl_verify = self.get_config_boolean("carbonblack_server_sslverify", False)
        server_url = self.get_config_string("carbonblack_server_url", "https://127.0.0.1")
        server_token = self.get_config_string("carbonblack_server_token", "")

        # log the interfaces for this computer for debugging purposes

        for interface_name in interfaces():
            ip4addresses = [i['addr'] for i in
                            ifaddresses(interface_name).setdefault(AF_INET, [{'addr':'No IPv4 addr'}] )]
            log.info('IPv4 addresses for %s: %s' % (interface_name, ', '.join(ip4addresses)))

        gateway_ip, gateway_dev = gateways()['default'].setdefault(AF_INET, ('No gateway', None))
        if gateway_dev:
            log.info('Default IPv4 route: %s via %s' % (gateway_ip, gateway_dev))
        else:
            log.warning('No default IPv4 route found')

        proxy_environment_variables = ['https_proxy', 'http_proxy', 'no_proxy']
        proxy_environment_variables.extend([v.upper() for v in proxy_environment_variables])

        for proxy_env in proxy_environment_variables:
            if os.getenv(proxy_env):
                log.info('Found proxy configuration: %s = %s' % (proxy_env, os.getenv(proxy_env)))

        '''
                try:
                    # here we just need to make one HTTP request in order to work around an issue where we get a file not
                    # found exception on unicode.so after the fork() from the requests library when we package with pyinstaller.
                    log.info("here")
                    cb = CbResponseAPI(url=server_url, token=server_token, ssl_verify=False)
                    cb.info()
                except Exception as e:
                    log.info("here1")
                    pass
                    # raise ConfigurationError("Could not create CbAPI instance to %s: %s" % (server_url, e.message))
        '''

        # call on_starting just before we call run()
        self.on_starting()

        if self.debug:
            log.info("Starting %s in the foreground, in debug mode" % self.name)
            self.run()
        else:
            # Start the daemon
            self.daemonize()
            try:
                self.run()
            except Exception as e:
                self.fatal(e)

        log.info("the daemon has stopped")

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

        log.info("daemon stopping...")

        # Try killing the daemon process
        try:
            while 1:
                os.kill(pid, SIGTERM)
                time.sleep(0.1)
        except OSError, err:
            err = str(err)
            if err.find("No such process") > 0:
                self.delpid()
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
            raise ConfigurationError("could not locate config file: %s" % configfile or "None")

        log.debug("parsing configuration")
        self.cfg = ConfigParser.RawConfigParser()
        self.cfg.read(configfile)

        # keeping self.options for backwards compatibility with older integrations
        for section in self.cfg.sections():
            self.options[section] = {}
            log.debug("section: %s" % section)
            for option in self.cfg.options(section):
                self.options[section][option] = self.cfg.get(section, option)
                log.debug("   %s: %s" % (option, self.cfg.get(section, option)))

    def __initialize_daemon(self):
        """
        Initialized common variables and objects that are needed by start and stop
        """

        if not self.__is_daemon_initialized:
            if self.pidfile is None:
                pid_path = "/var/run/cb/integrations/"
                cbint.utils.filesystem.ensure_directory_exists(pid_path)
                self.pidfile = "%s%s.pid" % (pid_path, self.name)

            self.__is_daemon_initialized = True

    def __initialize_logging(self):
        if not self.__is_logging_initialized:

            if self.logfile is None:
                log_path = "/var/log/cb/integrations/%s/" % self.name
                cbint.utils.filesystem.ensure_directory_exists(log_path)
                self.logfile = "%s%s.log" % (log_path, self.name)

            rlh = RotatingFileHandler(self.logfile, maxBytes=524288, backupCount=10)
            rlh.setFormatter(logging.Formatter(fmt="%(asctime)s: %(module)s: %(levelname)s: %(message)s"))
            log.addHandler(rlh)

        self.__is_logging_initialized = True

    def get_config_string(self, config_key, default_value=None):
        if self.cfg.has_option("bridge", config_key):
            return self.cfg.get("bridge", config_key)
        else:
            return default_value

    def get_config_boolean(self, config_key, default_value=False):
        if self.cfg.has_option("bridge", config_key):
            return self.cfg.getboolean("bridge", config_key)
        else:
            return default_value

    def get_config_integer(self, config_key, default_value=0):
        if self.cfg.has_option("bridge", config_key):
            return self.cfg.getint("bridge", config_key)
        else:
            return default_value

    def check_required_options(self, required_options):
        for option in required_options:
            if not self.cfg.has_option("bridge", option):
                raise ConfigurationError("Configuration file does not have required option %s in [bridge] section" %
                                         option)

