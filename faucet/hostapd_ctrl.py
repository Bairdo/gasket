"""hostpad socket interface classes.
"""
# pytype: disable=none-attr
# pytype: disable=attribute-error
# pytype: disable=name-error
# pytype: disable=wrong-keyword-args

import socket
import uuid


class HostapdCtrl(object):
    """Abstract class for the control interface to hostapd.
    May be either a UNIX socket, or UDP (IPv4 or IPv6).
    """
    soc = None
    logger = None
    cookie = None

    def request(self, cmd):
        """
        Args:
            cmd (str): command string to send.
        Returns:
            returns result of cmd.
        """
        if self.cookie:
            cmd = '%s %s' % (self.cookie, cmd)
        self.soc.send(cmd.encode())

        return self.receive(size=4096).strip()

    def attach(self):
        """Sends the 'attach' command to hostapd.
        Has the effect of subscribing to hostapd's unsolicited
        events.
        Returns:
            True if successful. False otherwise.
        """
        d = self.request('ATTACH')
        return self._returned_ok(d)

    def dettach(self):
        """Detatches the socket from hostapd -
        unsubscribes from hostapd's unsolicited events.
        """
        d = self.request('DETACH')
        return self._returned_ok(d)

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
        d = self.request('GET_CONFIG')
        return self._to_dict(d)

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
        return True
#        d = self.request('DEAUTHENTICATE %s' % mac)
#        return self._returned_ok(d)

    def disassociate(self, mac):
        """Disassociate a station. Not Currently implemented.
        Args:
            mac (str): MAC address of station.
        Returns:
            True if successful, False otherwise.
        """
#        d = self.request('DISASSOCIATE %s' % mac)
#       return self._returned_ok(d)
        return True

    def ping(self):
        """pings hostapd
        Returns:
            True if 'PONG' is received, false otherwise.
        """
        d = self.request('PING')
        self.logger.debug('PING - %s', d)
        return d == 'PONG'

    def _to_dict(self, d):
        dic = {}
        for s in d.split('\\n'):
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
        return str(self.soc.recv(size))

    def close(self):
        """Close the underlying control socket.
        """
        self.soc.close()

    def set_timeout(self, secs):
        """Set the timeout of the socket
        """
        self.soc.settimeout(secs)

    @staticmethod
    def _returned_ok(d):
        return d == 'OK'

class HostapdCtrlUNIX(HostapdCtrl):
    """UNIX socket interface class.
    """

    def __init__(self, path, logger):
        self.logger = logger
        logger.info('hctrl')
        self.soc = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        logger.info('connecting')
        if len(path) > 107:
            logger.critical('hostapd ctrl socket path must be <= 108 bytes (including null terminator), was; %d bytes, %s',
                            len(path), path)
            raise RuntimeError('hostapd ctrl socket path must be <= 108 bytes (including null terminator), was; %d bytes, %s' %
                               (len(path), path))
        try:
            self.soc.connect(path)
        except FileNotFoundError as e:
            logger.error('Unable to connect to socket. FileNotFoundError %s' % path)
            raise

        logger.info('connected')
        tmpfile = '/tmp/%s' % str(uuid.uuid4())
        try:
            self.soc.bind(tmpfile)
            logger.info('bound')
        except OSError as e:
            logger.error('Unable to bind to file: %s' % tmpfile)
            raise e


class HostapdCtrlUDP(HostapdCtrl):
    """UDP socket interface class
    """

    def __init__(self, family, sockaddr, logger):
        self.logger = logger
        logger.info('hctrl')
        self.soc = socket.socket(family, socket.SOCK_DGRAM)
        logger.info('connecting')
        try:
            self.soc.connect(sockaddr)
        # pytype: disable=name-error
        except FileNotFoundError as e:
            logger.error('Unable to connect to udp socket. sockaddr %s' % sockaddr)
            raise
        logger.info('connected')
        try:
            # TODO is this right?
            self.soc.bind(sockaddr)
            logger.info('bound')
        except OSError as e:
            logger.error('Unable to bind to udp socket. sockaddr %s' % sockaddr)
            raise e
        self.cookie = self.get_cookie()

    def get_cookie(self):
        """Get cookie for this control interface.
        Returns:
            str cookie.
        """
        return str(self.request('GET_COOKIE'))


def request_socket_udp(host, port, logger):
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
    return HostapdCtrlUDP(addrinfo[0], addrinfo[4], logger)


def unsolicited_socket_udp(host, port, logger):
    """Create a HostapdCtrlUDP class, and attaches for receiveing
    unsolicited events.
    Args:
        host (str): ipv4/ipv6/hostname of remote.
        port (int): port number
        logger (logger): logger object
    Returns:
        HostapdCtrlUDP object
    """
    s = request_socket_udp(host, port, logger)
    s.attach()
    return s


def request_socket_unix(path, logger):
    """Create a HostapdCtrlUNIX class.
    Args:
        path (str): pathname to UNIX socket.
        logger (logger): logger object
    Returns:
        HostapdCtrlUNIX object
    """
    return HostapdCtrlUNIX(path, logger)


def unsolicited_socket_unix(path, logger):
    """Create a HostapdCtrlUNIX class, and attaches for receiving
    unsolicited events.
    Args:
        path (str): pathname to UNIX socket.
        logger (logger): logger object
    Returns:
        HostapdCtrlUNIX object
    """
    s = request_socket_unix(path, logger)
    s.attach()
    s.set_timeout(1)
    return s
