import os

def validate_ip_address(addr: str):
    import socket
    try:
        socket.inet_aton(addr)
        return True
    except socket.error:
        return False

def inside_docker():
    """
    :return: if we are running inside docker
    """
    if os.path.exists('/.dockerenv'):
        return True
    else:
        return False