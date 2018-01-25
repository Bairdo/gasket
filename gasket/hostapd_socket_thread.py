"""Configuration for a hostapd socket."""
import logging
import os
import socket
import threading

from gasket.gasket_conf_utils import validate_ip_address
from gasket.gasket_conf_utils import validate_port
from gasket import auth_app_utils
from gasket import gasket_conf
from gasket import hostapd_ctrl
from gasket import work_item

# TODO remove these hardcoded numbers.
FAUCET_ENTERPRISE_NUMBER = 12345
FAUCET_RADIUS_ATTRIBUTE_ACL_TYPE = 1


class HostapdSocketThread(gasket_conf.GasketConf, threading.Thread):
    """Stores state related to a hostapd instance.
    """
    logger_location = None
    logger = None
    hapd_req = None
    hapd_unsol = None
    work_queue = None
    udp = True

    name = None
    description = None
    remote_host = None
    remote_port = None
    unix_socket_path = None
    unsolicited_bind_address = None
    request_bind_address = None
    request_bind_port = None
    unsolicited_bind_port = None
    request_timeout = None
    unsolicited_timeout = None
    server_pinging = None
    ssid = None


    defaults = {
        'name': None,
        'description': None,
        'unix_socket_path': None,
        'remote_host': None,
        'remote_port': None,
        'unsolicited_bind_address': None,
        'request_bind_address': None,
        'request_bind_port': None,
        'unsolicited_bind_port': None,
        'request_timeout': 5,
        'unsolicited_timeout': 5,
        'server_pinging': True,
        'ssid': None,
    }

    defaults_types = {
        'name': str,
        'description': str,
        'unix_socket_path': str,
        'remote_host': str,
        'remote_port': int,
        'unsolicited_bind_address': str,
        'request_bind_address': str,
        'request_bind_port': int,
        'unsolicited_bind_port': int,
        'request_timeout': int,
        'unsolicited_timeout': int,
        'server_pinging': bool,
        'ssid': str,
    }


    def __init__(self, _id, config, work_queue, logger_location):
        self.logger_location = logger_location
        threading.Thread.__init__(self)
        gasket_conf.GasketConf.__init__(self, _id, config)
        self.work_queue = work_queue

        self.logger.info('about to start socket')
        if self.udp:
            self._init_udp_sockets()
        else:
            self._init_unix_sockets()
        self.logger.info('checked config')

    def check_config(self):
        validate_port(self.remote_port)
        validate_ip_address(self.remote_host)

        if self.unix_socket_path:
            self.udp = False
            assert self.remote_host is None and self.remote_port is None

        if self.request_bind_address:
            validate_ip_address(self.request_bind_address)
        if self.request_bind_port:
            validate_port(self.request_bind_port)
        if self.unsolicited_bind_address:
            validate_ip_address(self.unsolicited_bind_address)
        if self.unsolicited_bind_port:
            validate_port(self.unsolicited_bind_port)

    def set_defaults(self):
        super().set_defaults()
        self._set_default('name', self._id)
        self._set_default('description', self.name)
        self.logger = auth_app_utils.get_logger('hostapd-%s' % self.name, self.logger_location, logging.DEBUG, 1)

    def run(self):
        """Main loop, waits for messages from hostapd ctl socket,
        and processes them.
        """
        self.logger.info('sockets initiated')
        while True:
            self.logger.info('waiting for receive')
            data = ""
            try:
                data = str(self.hapd_unsol.receive())
            except socket.timeout:
                # icmp ping the hostapd server.
                # if return ok server is reachable. but maybe app crashed.
                self.ping(self.hapd_unsol)
                # restart the socket, will need new cookie.
                # What to do if this ping fails. close? and restart.
                continue
            self.logger.info('received message: %s' % data)
            if 'CTRL-EVENT-EAP-SUCCESS' in data:
                self.logger.info('success message')
                mac = data.split()[1].replace("'", '')
                try:
                    sta = self.hapd_req.get_sta(mac)
                except socket.timeout:
                    self.logger.warning('request socket timed out while getting mib for mac: %s' % mac)
                    continue

                if 'AccessAccept:Vendor-Specific:%d:%d' \
                                        % (FAUCET_ENTERPRISE_NUMBER,
                                           FAUCET_RADIUS_ATTRIBUTE_ACL_TYPE) in sta:
                    radius_acl_list = sta['AccessAccept:Vendor-Specific:%d:%d'
                                          % (FAUCET_ENTERPRISE_NUMBER,
                                             FAUCET_RADIUS_ATTRIBUTE_ACL_TYPE)].split(',')
                else:
                    self.logger.info('AccessAccept:Vendor-Specific:%d:%d not in mib'
                                     % (FAUCET_ENTERPRISE_NUMBER,
                                        FAUCET_RADIUS_ATTRIBUTE_ACL_TYPE))
                    continue
                username = sta['dot1xAuthSessionUserName']
                # and add mac, username, radius_acl_list to work queue.
                self.logger.info('work about to be given to queue')
                self.work_queue.put(work_item.AuthWorkItem(mac,
                                                           username,
                                                           radius_acl_list,
                                                           self.name))
                self.logger.info('work given to queue')
            elif 'AP-STA-DISCONNECTED' in data:
                self.logger.info('%s disconnected message', data)
                mac = data.split()[1].replace("'", '')
                # and add mac to the work queue for deauth. maybe add which hostapd it came from
                self.work_queue.put(work_item.DeauthWorkItem(mac, self.name))
            else:
                self.logger.info('unknown message %s', data)


    def _init_udp_sockets(self):
        self.logger.info('initiating UDP socket for hostapd ctrl')
        self.hapd_req = hostapd_ctrl.request_socket_udp(self.remote_host, self.remote_port,
                                              self.request_bind_address,
                                              self.request_bind_port,
                                              self.request_timeout,
                                              self.logger)

        self.hapd_unsol = hostapd_ctrl.unsolicited_socket_udp(self.remote_host, self.remote_port,
                                                self.unsolicited_bind_address,
                                                self.unsolicited_bind_port,
                                                self.unsolicited_timeout,
                                                self.logger)

    def ping(self, _socket):
        """Sends a ping packet to the hostapd socket. if it times out sends a ICMP ping to the host.
        Args:
            socket (HostapdCtrlUDP)
        Returns:
            True if hostapd ping returns true - everything is all good
            2 if ping fail, but ICMP ping is successful.
            4 if ping fail, and ICMP ping is unsuccessful.
        """
        try:
            if _socket.ping():
                return True
        except socket.timeout as ex:
            self.logged.info('Caught exception %s ignoring' % ex)
        return self.icmp_ping(_socket.get_host())

    def icmp_ping(self, host, count=1):
        """Send ICMP ping to the host.
        Args:
            host (str): ip address or hostname.
            count (int): number of pings to send.
        """
        if os.system('ping %s -c%s -W 2 > /dev/null 2&>1' % (host, count)) == 0:
            self.logger.info('machine %s is reachable' % host)
            return 2
        else:
            self.logger.info('machine %s is unreachable' % host)
            return 3


    def _init_unix_sockets(self):
        self.logger.info('initiating UNIX socket for hostapd ctrl')
        self.hapd_req = self.request_socket_unix(self.unix_socket_path, self.request_timeout, self.logger)
        self.hapd_unsol = self.unsolicited_socket_unix(self.unix_socket_path, self.unsolicited_timeout, self.logger)

