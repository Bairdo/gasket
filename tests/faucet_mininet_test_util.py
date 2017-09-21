#!/usr/bin/env python

"""Standalone utility functions for Mininet tests."""

import collections
import os
import socket
import subprocess
import time


LOCALHOST = u'127.0.0.1'
FAUCET_DIR = os.getenv('FAUCET_DIR', '../faucet')
RESERVED_FOR_TESTS_PORTS = (179, 5001, 5002, 6633, 6653)
MIN_PORT_AGE = max(int(open(
    '/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_time_wait').read()) / 2, 30)


def flat_test_name(_id):
    """Return short form test name from TestCase ID."""
    return '-'.join(_id.split('.')[1:])


def tcp_listening_cmd(port, ipv=4, state='LISTEN'):
    """Return a command line for lsof for PIDs with specified TCP state."""
    return 'lsof -b -P -n -t -sTCP:%s -i %u -a -i tcp:%u' % (state, ipv, port)


def mininet_dpid(int_dpid):
    """Return stringified hex version, of int DPID for mininet."""
    return str('%x' % int(int_dpid))


def str_int_dpid(str_dpid):
    """Return stringified int version, of int or hex DPID from YAML."""
    str_dpid = str(str_dpid)
    if str_dpid.startswith('0x'):
        return str(int(str_dpid, 16))
    return str(int(str_dpid))


def receive_sock_line(sock):
    """Receive a \n terminated line from a socket."""
    buf = ''
    while buf.find('\n') <= -1:
        buf = buf + sock.recv(1024)
    return buf.strip()


def tcp_listening(port):
    """Return True if any process listening on a port."""
    DEVNULL = open(os.devnull, 'w')
    return subprocess.call(
        tcp_listening_cmd(port).split(), stdout=DEVNULL, stderr=DEVNULL, close_fds=True) == 0


def find_free_port(ports_socket, name):
    """Retrieve a free TCP port from test server."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(ports_socket)
    sock.sendall('GET,%s\n' % name)
    buf = receive_sock_line(sock)
    return [int(x) for x in buf.strip().split()]


def return_free_ports(ports_socket, name):
    """Notify test server that all ports under name are released."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(ports_socket)
    sock.sendall('PUT,%s\n' % name)


def serve_ports(ports_socket, start_free_ports, min_free_ports):
    """Implement a TCP server to dispense free TCP ports."""
    ports_q = collections.deque()
    free_ports = set()
    port_age = {}

    def get_port():
        while True:
            free_socket = socket.socket()
            free_socket.bind(('', 0))
            free_port = free_socket.getsockname()[1]
            free_socket.close()
            if free_port < 1024:
                continue
            if free_port in RESERVED_FOR_TESTS_PORTS:
                continue
            if free_port in free_ports:
                continue
            break
        free_ports.add(free_port)
        port_age[free_port] = time.time()
        return free_port

    def queue_free_ports(min_queue_size):
        while len(ports_q) < min_queue_size:
            port = get_port()
            ports_q.append(port)
            port_age[port] = time.time()
            time.sleep(0.1)

    queue_free_ports(start_free_ports)
    ports_served = 0
    ports_by_name = collections.defaultdict(set)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(ports_socket)
    sock.listen(1)

    while True:
        connection, _ = sock.accept()
        command, name = receive_sock_line(connection).split(',')
        if command == 'PUT':
            for port in ports_by_name[name]:
                ports_q.append(port)
                port_age[port] = time.time()
            del ports_by_name[name]
        else:
            if len(ports_q) < min_free_ports:
                queue_free_ports(len(ports_q) + 1)
            while True:
                port = ports_q.popleft()
                if time.time() - port_age[port] > MIN_PORT_AGE:
                    break
                ports_q.append(port)
                time.sleep(1)
            ports_served += 1
            ports_by_name[name].add(port)
            # pylint: disable=no-member
            connection.sendall('%u %u\n' % (port, ports_served))
        connection.close()


def timeout_cmd(cmd, timeout):
    """Return a command line prefaced with a timeout wrappers and stdout/err unbuffered."""
    return 'timeout -sKILL %us stdbuf -o0 -e0 %s' % (timeout, cmd)


def timeout_soft_cmd(cmd, timeout):
    """Same as timeout_cmd buf using SIGTERM on timeout."""
    return 'timeout %us stdbuf -o0 -e0 %s' % (timeout, cmd)


def gen_config_global(num_vlans):
    """Generate the str for the CONFIG_GLOBAL variable
    Args:
        num_vlans (int): number of vlans on the portal port.
    Returns:
        str for CONFIG_GLOBAL
    """
    conf = """vlans:
    100:
        description: "untagged"
    1:
include:
    - {tmpdir}/faucet-acl.yaml"""

    return conf


def gen_config(num_vlans):
    """Generate the str for the CONFIG variable.
    Args:
        num_vlans (int): number of vlans on the portal port.
    Returns:
        str for CONFIG
    """
    conf = """
        timeout: 3000
        interfaces:
            %(port_1)d:
                name: portal
                native_vlan: 100
            %(port_2)d:
                name: gateway
                native_vlan: 100"""

    for i in range(3, num_vlans + 3):
        conf = """{0}
            %(port_{1})d:
                name: host{1}
                native_vlan: 100
                acl_in: port_faucet-1_%(port_{1})d""".format(conf, i)
    return conf


def gen_base_config(num_vlans):
    """Generate the base acl file usd by auth_app.
    Args:
        num_vlans (int): number of vlans on the portal port.
    Returns:
        str of base acl.
    """
    conf = """acls:"""
    # TODO can we not hardcode these output dl_dst mac adddresses for portal?
    for i in range(3, num_vlans + 3):
        port_acl = """
  port_faucet-1_{0}:
  - rule:
      dl_type: 0x888e
      actions:
        allow: 1
        output:
          dl_dst: 70:6f:72:74:61:6c
  - authed-rules
  - rule:
      actions:
        allow: 1
        output:
          dl_dst: 70:6f:72:74:61:6c""".format(i)

        conf = "{0}\n{1}""".format(conf, port_acl)

    return conf


def gen_faucet_acl(num_hosts):
    """Creates a string for faucet acls. each acl will be empty.
    But satisfies the requirement for each ports acl_in to be known.
    Args:
        num_hosts (int): number of ports to create acl for.
    Returns:
        (str)
    """
    conf = """acls:"""
    for i in range(3, num_hosts + 3):
        conf = """{0}
    port_faucet-1_%(port_{1})d:
        - rule:
            actions:
                allow: 0""".format(conf, i)

    return conf


def gen_port_map(num_ports):
    """Create the port_map dict with the number of ports.
    Args:
        num_ports (int): number of ports on faucet-1 switch.
    Returns:
        dict {'port_1': 1, 'port_2': 2,...}
    """
    port_map = {}
    for i in range(1, num_ports + 1):
        port_map['port_%d' % i] = i
    return port_map

