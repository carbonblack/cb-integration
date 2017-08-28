from cbapi.connection import CbAPISessionAdapter
import logging
import ssl
import sys
import requests


log = logging.getLogger(__name__)
tls_fatal_error_message = "This version of Python and OpenSSL do not support TLSv1.2. Exiting."
unknown_fatal_error_message = "Unknown error establishing TLSv1.2 session. Exiting."


def get_tlsv1_2_session(hostname=None):
    try:
        tls_adapter = CbAPISessionAdapter(force_tls_1_2=True)
    except ssl.SSLError:
        log.fatal(tls_fatal_error_message)
        sys.stderr.write(tls_fatal_error_message + "\n")
        sys.exit(1)
    except Exception:
        log.fatal(unknown_fatal_error_message)
        sys.stderr.write(unknown_fatal_error_message + "\n")
        sys.exit(1)

    s = requests.Session()
    s.mount("https://{}".format(hostname), tls_adapter)

    return s
