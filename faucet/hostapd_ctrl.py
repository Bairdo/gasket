# pytype: disable=none-attr
# pytype: disable=attribute-error
# pytype: disable=name-error
# pytype: disable=wrong-keyword-args
import random
import socket
import subprocess
import uuid


class HostapdCtrl(object):
    soc = None
    logger = None
    cookie = None

    def request(self, cmd):
        if self.cookie:
            cmd = '%s %s' % (self.cookie, cmd)
        self.soc.send(cmd.encode())

        d = self.receive(size=4096)
        return d

    def attach(self):
        d = self.request('ATTACH')
        if d == b'OK\n':
            return True
        return False

    def dettach(self):
        d = self.request('DETACH')
        return self._returned_ok(d)

    def mib(self):
        return self.request('MIB')
    
    def get_config(self):
        d = self.request('GET_CONFIG')
        return self._to_dict(d)

    def get_sta(self, mac):
        return self._to_dict(self.request('STA %s' % mac))

    def all_sta(self):
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
        return True
#        d = self.request('DEAUTHENTICATE %s' % mac)
#        return self._returned_ok(d)

    def disassociate(self, mac):
#        d = self.request('DISASSOCIATE %s' % mac)
#       return self._returned_ok(d)
        return True

    def _to_dict(self, d):
        dic = {}
        for s in d.split('\\n'):
            print((s))
            try:
                k, v = s.split('=')
                dic[k] = v
            except ValueError:
                self.logger.info('line: %s cannot be split by "="' % s)
                print(('line: %s cannot be split by "="' % s))
        return dic

    def _returned_ok(self, d):
        if d == b'OK\n':
            return True
        else:
            return False
    
    def receive(self, size=4096):
        return str(self.soc.recv(size))

    def close(self):
        self.soc.close()


class HostapdCtrlUnix(HostapdCtrl):

    def __init__(self, path, logger):
        self.logger = logger
        logger.info('hctrl')
        self.soc = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        logger.info('connecting')
        if len(path) > 107:
            logger.critical('hostapd ctrl socket path must be <= 108 bytes (including null terminator), was; %d bytes, %s' % (len(path), path))
            raise RuntimeError('hostapd ctrl socket path must be <= 108 bytes (including null terminator), was; %d bytes, %s' % (len(path), path))
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
            logger.error('Unable to bind to file: %' % tmpfile)
            raise e


class HostapdCtrlUDP(HostapdCtrl):

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
        return str(self.request('GET_COOKIE'))


def request_socket_udp(host, port, logger):
    # use the first addr found, if more than one 
    # (such as the case with hostnames that resolve to both ipv6 and ipv4).
    addrinfo = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)[0]
    return HostapdCtrlUDP(addrinfo[0], addrinfo[4], logger)


def unsolicited_socket_udp4(host, port, logger):
    s = request_socket_udp(host, port, logger)
    s.attach()
    return s


def request_socket_unix(path, logger):
    return HostapdCtrlUnix(path, logger)


def unsolicited_socket_unix(path, logger):
    s = request_socket_unix(path, logger)
    s.attach()
    return s