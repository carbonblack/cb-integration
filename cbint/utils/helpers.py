def validate_ip_address(addr: str):
    import socket
    try:
        socket.inet_aton(addr)
        return True
    except socket.error:
        return False

