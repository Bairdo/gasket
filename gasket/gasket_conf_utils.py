"""Helper functions for validating various configuration types.
"""
import logging
import socket


def validate_ip_address(addr):
    try:
        socket.inet_aton(addr)
    except socket.error:
        raise AssertionError("invalid ip address: %s" % addr)


def validate_port(port):
    assert port is None or 1 <= port <= 65535, "invalid port number: %s" % port


def get_log_level(log_level):
    if not log_level:
        return logging.INFO
    elif isinstance(log_level, int):
        return log_level
    elif log_level.upper() in ['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG']:
        return getattr(logging, log_level.upper())
    return logging.INFO
