
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
    if not server_info or not 'version' in server_info:
        return False
    else:
        server_version = server_info['version']
        if not check_version(version, server_version):
            return False
        else:
            return True