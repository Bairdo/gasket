"""Helper functions for validating various configuration types.
"""
import socket

def validate_ip_address(addr):
    try:
        socket.inet_aton(addr)
    except socket.error:
        raise AssertionError("invalid ip address: %s" % addr)


def validate_port(port):
    assert port is None or 1 <= port <= 64000, "invalid port number: %s" % port
