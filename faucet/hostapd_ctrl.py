
import random
import socket
import subprocess
import tempfile

class HostapdCtrl(object):
    soc = None
    logger = None
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
        # pytype: disable=name-error
        except FileNotFoundError as e:
            logger.error('Unable to connect to socket. FileNotFoundError %s' % path)
            raise
        logger.info('connected')
        fp = tempfile.NamedTemporaryFile()
        self.soc.bind(fp.name)
        logger.info('bound')

    def request(self, cmd):
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
        # pytype: disable=attribute-error
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


def request_socket(path, logger):
    return HostapdCtrl(path, logger)

def unsolicited_socket(path, logger):
    s = HostapdCtrl(path, logger)
    s.attach()
    return s
