"""hostpad socket interface classes.
"""
# pytype: disable=none-attr
# pytype: disable=attribute-error
# pytype: disable=name-error
# pytype: disable=wrong-keyword-args

import socket
from datetime import datetime
import os
import time

class HostapdCtrl(object):
    """Abstract class for the control interface to hostapd.
    May be either a UNIX socket, or UDP (IPv4 or IPv6).
    """
    soc = None
    logger = None
    cookie = None
    ifname = None
    local_unix_sock_path = None
    attached = False
    should_attach = False
    socket_attempts = 500
    timeout = 0

    def request(self, cmd):
        """
        Args:
            cmd (str): command string to send.
        Returns:
            returns result of cmd.
        """
        if self.cookie:
            cmd = 'COOKIE=%s %s' % (self.cookie, cmd)
        self.logger.debug('request is "%s"', cmd)
        self.soc.send(cmd.encode())

        return self.receive(size=4096)

    def attach(self):
        """Sends the 'attach' command to hostapd.
        Has the effect of subscribing to hostapd's unsolicited
        events.
        Returns:
            True if successful. False otherwise.
        """
        self.attached = self._returned_ok(self.request('ATTACH'))
        return self.attached

    def detach(self):
        """Detatches the socket from hostapd -
        unsubscribes from hostapd's unsolicited events.
        Returns:
            True if detach successful or not attached. false otherwise.
        """
        if self.attached:
            self.attached = not self._returned_ok(self.request('DETACH'))
            return self.attached
        return True

    def mib(self):
        """Get MIB variables (dot1x, dot11, radius)
        Returns:
            str
        """
        return self.request('MIB')

    def get_config(self):
        """Show current running config
        Returns:
            running config converted to dict.
        """
        return self._to_dict(self.request('GET_CONFIG'))

    def get_sta(self, mac):
        """Get MIB variables for one station
        Args:
            mac (str): addr of station to request MIB
        Returns:
            dict of station MIB
        """
        return self._to_dict(self.request('STA %s' % mac))

    def all_sta(self):
        """Get MIB variables for all stations.
        Returns:
            list of station dict MIBs
        """
        stas = {}
        d = self.request('STA-FIRST')
        mac_addr = d.split()[0]
        data = d.split()[1:]
        stas[mac_addr] = self._to_dict(data)

        while True:
            d = self.request('STA-NEXT %s' % mac_addr)
            if d == b'FAIL\n':
                break
            mac_addr = d.split()[0]
            data = d.split()[1:]
            stas[mac_addr] = self._to_dict(data)
        return stas

    def deauthenticate(self, mac):
        """Deauthenticate a station. Not Currently implemented.
        Args:
            mac (str): MAC address of station.
        Returns:
            True if successful, False otherwise.
        """
        return self._returned_ok(self.request('DEAUTHENTICATE %s' % mac))

    def disassociate(self, mac):
        """Disassociate a station. Not Currently implemented.
        Args:
            mac (str): MAC address of station.
        Returns:
            True if successful, False otherwise.
        """
        return self._returned_ok(self.request('DISASSOCIATE %s' % mac))

    def send_ping(self):
        """pings hostapd
        Returns:
            True if 'PONG' is received, false otherwise.
        """
        try:
            d = self.request('PING')
        except (socket.timeout, ConnectionRefusedError):
            self.logger.debug('ping timed out.')
            return False
        self.logger.debug('PING - "%s"', d)
        return d == 'PONG\n'

    def ping(self):
        """Attempts to send a ping, if fails attempts to reconnect until successful.
        """
        while True:
            if self.soc:
                if not self.send_ping():
                    self.logger.info('Connection to hostapd lost. Retrying to connect')
                    self.close()
                else:
                    return

            if not self.soc and self.reconnect(self.ifname):
                self.logger.info('Connection to hostapd re-established.')
                break
            time.sleep(2)

    def get_status(self):
        """Get hostapd status dictionary.
        Returns:
            dictionary of hostapd status
        """
        return self._to_dict(self.request('STATUS'))

    def _to_dict(self, d):
        self.logger.debug(d)
        dic = {}
        for s in d.split('\n'):
            try:
                k, v = s.split('=')
                dic[k] = v
            except ValueError:
                self.logger.info('line: %s cannot be split by "="', s)
        return dic

    def receive(self, size=4096):
        """Receives size bytes from socket. (Blocking)
        Args:
            size (int): number of bytes to recieve.
        Returns:
            str of data.
        """
        return self.soc.recv(size).decode()

    def set_timeout(self, secs):
        """Set the timeout of the socket
        """
        self.soc.settimeout(secs)

    @staticmethod
    def _returned_ok(data):
        return data == 'OK\n'


class HostapdCtrlUNIX(HostapdCtrl):
    """UNIX socket interface class.
    """

    def __init__(self, ifname, timeout, logger, attached=False):
        self.logger = logger
        self.should_attach = attached
        self.ifname = ifname
        self.timeout = timeout

        self.logger.info('connecting')
        while not self.reconnect(ifname):
            time.sleep(1)

        self.logger.info('Connection established')

    def reconnect(self, ifname):
        """Attempts to connect and attach to hostapd socket.
        Args:
            ifname (str): ctrl_path which is the name of remote hostapd network
            interface to listen for messages
        Returns:
            True - success.
            False - Failure.
        """
        self.close()

        tmpfile = '/tmp/auth-sock-%s' % datetime.now().microsecond
        self.local_unix_sock_path = tmpfile

        if not self.open_connection(ifname, tmpfile):
            return False
        if self.should_attach:
            if not self.attach():
                return False
            # maybe do something here. if not attached and should be.
        return True

    def open_connection(self, ctrl_path, cli_path):
        """Attempts to open the socket to the hostapd control interface.
        Args:
            ctrl_path (str): name of the remote hostapd network interface socket.
            cli_path (str): path to bind (client) location of socket.
        Returns:
            True: success
            False: Failure
        """
        self.soc = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.set_timeout(self.timeout)

        if len(cli_path) > 107:
            self.logger.critical('hostapd ctrl socket path must be <= 108 bytes (including null terminator), was: %d bytes, %s',
                                 len(cli_path), cli_path)
            raise RuntimeError('hostapd ctrl socket path must be <= 108 bytes (including null terminator), was: %d bytes, %s' %
                               (len(cli_path), cli_path))

        self.logger.info('path length is fine.')
        for i in range(3):
            try:
                self.soc.bind(cli_path)
                self.logger.info('Bound to UNIX Socket: %s', cli_path)
                break
            except OSError as e:
                self.logger.error('Unable to bind to UNIX Socket: %s' % cli_path)
                self.logger.exception(e)
                if i < 2:
                    os.remove(cli_path)
                    continue
                self.soc.close()
                self.soc = None
                return False

        try:
            self.soc.connect(ctrl_path)
            self.logger.info('Connected')
        except FileNotFoundError as e:
            self.logger.error('Unable to connect to socket. FileNotFoundError %s' % ctrl_path)
            self.soc.close()
            os.remove(cli_path)
            self.soc = None
            return False

        self.logger.info('Connected to UNIX Socket: %s', ctrl_path)
        return True

    def close(self):
        """Close the underlying control socket.
        """
        if self.soc is None:
            return
        self.soc.close()
        self.logger.debug('socket closed')
        os.remove(self.local_unix_sock_path)
        self.logger.debug('unix socket path removed')
        self.soc = None


class HostapdCtrlUDP(HostapdCtrl):
    """UDP socket interface class
    """

    host = None
    family = None
    sockaddr = None
    bind_address = None
    bind_port = None

    def __init__(self, ifname, family, sockaddr,
                 bind_address, bind_port,
                 timeout, logger, attached=False):
        self.logger = logger
        self.should_attach = attached
        self.ifname = ifname

        self.family = family
        self.sockaddr = sockaddr

        self.bind_address = bind_address
        self.bind_port = bind_port

        self.timeout = timeout
        self.logger.info('connecting')
        while not self.reconnect(ifname):
            time.sleep(1)

        self.logger.info('Connection established')

    def reconnect(self, ifname):
        """Attempts to connect and attach to hostapd socket.
        Args:
            ifname (str): name of (hostapd) network interface to
            listen for messages
        Returns:
            True - success.
            False - Failure.
        """
        self.close()

        if not self.open_connection(ifname):
            return False
        if self.should_attach:
            if not self.attach():
                # maybe close here.
                return False
        return True

    def open_connection(self, ifname):
        """Attempts to open socket to remote hostapd.
        Args:
            ifname (str): currently unused, but should be name of interface on remote hostapd.
        Returns:
            True: success
            False: Failure
        """
        self.soc = socket.socket(self.family, socket.SOCK_DGRAM)
        self.set_timeout(self.timeout)

        for i in range(3):
            try:
                if self.bind_address is not None and self.bind_port is not None:
                    self.soc.bind((self.bind_address, int(self.bind_port)))
            # pytype: disable=name-error
            except OSError:
                #TODO what exception should this be?
                self.logger.error('Unable to bind to address: %s port: %d',
                                  self.bind_address, self.bind_port)
                if i < 2:
                    continue
                self.soc.close()
                self.soc = None
                return False

            try:
                self.soc.connect(self.sockaddr)
                cookie = self.get_cookie()
                self.logger.info(cookie)
                self.cookie = cookie.lstrip("COOKIE=")
                self.logger.info('UDP Socket Cookie is %s', self.cookie)
            except socket.timeout:
                self.logger.debug("Couldn't connect (get cookie) to UDP socket %s", self.sockaddr)
                if i < 2:
                    continue
                self.soc.close()
                self.soc = None
                self.cookie = None
                return False
            self.logger.info('Connected to UDP Socket: %s', self.sockaddr)
            return True

    def get_cookie(self):
        """Get cookie for this control interface.
        Returns:
            str cookie.
        """
        return self.request('GET_COOKIE')

    def close(self):
        """Closes and resets socket
        """
        if self.soc:
            self.soc.close()
            self.soc = None
        self.cookie = None


def request_socket_udp(ifname, host, port, bind_address, bind_port,
                       timeout, logger, attached=False):
    """Create a HostapdCtrlUDP class.
    Args:
        host (str): ipv4/ipv6/hostname of remote.
        port (int): port number
        logger (logger): logger object
    Returns:
        HostapdCtrlUDP object
    """
    # use the first addr found, if more than one
    # (such as the case with hostnames that resolve to both ipv6 and ipv4).
    addrinfo = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)[0]
    return HostapdCtrlUDP(ifname, addrinfo[0], addrinfo[4],
                          bind_address, bind_port,
                          timeout, logger,
                          attached=attached)


def unsolicited_socket_udp(ifname, host, port, bind_address, bind_port,
                           timeout, logger):
    """Create a HostapdCtrlUDP class, and attaches for receiveing
    unsolicited events.
    Args:
        host (str): ipv4/ipv6/hostname of remote.
        port (int): port number
        logger (logger): logger object
    Returns:
        HostapdCtrlUDP object
    """
    return request_socket_udp(ifname, host, port,
                              bind_address, bind_port,
                              timeout, logger, attached=True)


def request_socket_unix(path, timeout, logger, attached=False):
    """Create a HostapdCtrlUNIX class.
    Args:
        path (str): pathname to UNIX socket.
        logger (logger): logger object
    Returns:
        HostapdCtrlUNIX object
    """
    return HostapdCtrlUNIX(path, timeout, logger, attached=attached)


def unsolicited_socket_unix(path, timeout, logger):
    """Create a HostapdCtrlUNIX class, and attaches for receiving
    unsolicited events.
    Args:
        path (str): pathname to UNIX socket.
        logger (logger): logger object
    Returns:
        HostapdCtrlUNIX object
    """
    return request_socket_unix(path, timeout, logger, attached=True)
