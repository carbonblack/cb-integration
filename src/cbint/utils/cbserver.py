import logging

log = logging.getLogger(__name__)

def check_version(required_version, supplied_version):
    """
    tests to ensure that the supplied version is >= the required version
    """
    required_parts = required_version.split('.')
    supplied_parts = supplied_version.split('.')
    for counter, part in enumerate(required_parts):
        compare_result = cmp(int(part), int(supplied_parts[counter]))
        if compare_result > 0:
            return False
        elif compare_result < 0:
            return True
        else:
            continue

    return True


def is_server_at_least(cb_api, version):
    """
    using the provided cb_api reference, verifies that the connected server
    version is greater than or equal to the provided version string
    """
    server_info = cb_api.info()

    if not server_info or 'version' not in server_info:
        return False
    else:
        server_version = server_info['version']
        if not check_version(version, server_version):
            return False
        else:
            return True

'''
def connect_local_cbapi():
    from cb.utils import Config
    from cb.utils.db import db_session_context
    from cb.db.core_models import User

    cfg = Config()
    cfg.load('/etc/cb/cb.conf')
    db_session_context = db_session_context(cfg)
    db_session = db_session_context.get()

    user = db_session.query(User).filter(User.global_admin == True).first()
    api_token = user.auth_token
    db_session_context.finish()

    port = cfg.NginxWebApiHttpPort
    return cbapi.CbApi('https://{0:s}:{1:d}/'.format('127.0.0.1', port), token=api_token, ssl_verify=False)
'''