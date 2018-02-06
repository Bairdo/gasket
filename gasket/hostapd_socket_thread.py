"""Configuration for a hostapd socket."""
import logging
import socket
import threading

from gasket import auth_app_utils
from gasket import hostapd_ctrl
from gasket import work_item

# TODO remove these hardcoded numbers.
FAUCET_ENTERPRISE_NUMBER = 12345
FAUCET_RADIUS_ATTRIBUTE_ACL_TYPE = 1


class HostapdSocketThread(threading.Thread):
    """Stores state related to a hostapd instance.
    """
    logger = None

    conf = None
    request_sock = None
    unsolicited_sock = None
    work_queue = None
    udp = False
    stop = False

    def __init__(self, conf, work_queue, logger_location):
        super().__init__()
        self.conf = conf
        self.logger = auth_app_utils.get_logger(self.conf.name,
                                                logger_location,
                                                logging.DEBUG,
                                                1)
        self.work_queue = work_queue

    def run(self):
        """Main loop, waits for messages from hostapd ctl socket,
        and processes them.
        """
        self.logger.info('run run')

        self.logger.info('about to start socket')
        if self.conf.udp:
            self._init_udp_sockets()
        else:
            try:
                self._init_unix_sockets()
            except Exception as e:
                self.logger.exception(e)
                raise

        try:
            self.logger.info('sockets initiated')
            while not self.stop:
                self.logger.info('waiting for receive')
                data = ""
                try:
                    data = str(self.unsolicited_sock.receive())
                except socket.timeout:
                    self.request_sock.ping()
                    continue
                self.logger.info('received message: %s', data)
                if 'CTRL-EVENT-EAP-SUCCESS' in data:
                    self.logger.info('success message')
                    mac = data.split()[1].replace("'", '')
                    try:
                        sta = self.request_sock.get_sta(mac)
                    except socket.timeout:
                        self.logger.warning('request socket timed out while getting mib for mac: %s',
                                            mac)
                        continue

                    if 'AccessAccept:Vendor-Specific:%d:%d' \
                                            % (FAUCET_ENTERPRISE_NUMBER,
                                               FAUCET_RADIUS_ATTRIBUTE_ACL_TYPE) in sta:
                        radius_acl_list = sta['AccessAccept:Vendor-Specific:%d:%d'
                                              % (FAUCET_ENTERPRISE_NUMBER,
                                                 FAUCET_RADIUS_ATTRIBUTE_ACL_TYPE)].split(',')
                    else:
                        self.logger.info('AccessAccept:Vendor-Specific:%d:%d not in mib',
                                         FAUCET_ENTERPRISE_NUMBER,
                                         FAUCET_RADIUS_ATTRIBUTE_ACL_TYPE)
                        continue
                    username = sta['dot1xAuthSessionUserName']
                    # and add mac, username, radius_acl_list to work queue.
                    self.logger.info('work about to be given to queue')
                    self.work_queue.put(work_item.AuthWorkItem(mac,
                                                               username,
                                                               radius_acl_list,
                                                               self.conf.name))
                    self.logger.info('work given to queue')
                elif 'AP-STA-DISCONNECTED' in data:
                    self.logger.info('%s disconnected message', data)
                    mac = data.split()[1].replace("'", '')
                    # and add mac to the work queue for deauth. maybe add which hostapd it came from
                    self.work_queue.put(work_item.DeauthWorkItem(mac, self.conf.name))
                else:
                    self.logger.info('unknown message %s', data)
        except Exception as e:
            self.logger.info('exception in run.')
            self.logger.exception(e)
            return

    def kill(self):
        # TODO Does this even work? - does hostapd detatch the socket.
        self.request_sock.close()
        self.unsolicited_sock.detach()
        self.unsolicited_sock.close()
        self.stop = True

    def _init_udp_sockets(self):
        self.logger.info('initiating UDP socket for hostapd ctrl')
        self.request_sock = hostapd_ctrl.request_socket_udp(self.conf.ifname,
                                                            self.conf.remote_host,
                                                            self.conf.remote_port,
                                                            self.conf.request_bind_address,
                                                            self.conf.request_bind_port,
                                                            self.conf.request_timeout,
                                                            self.logger)

        self.unsolicited_sock = hostapd_ctrl.unsolicited_socket_udp(self.conf.ifname,
                                                                    self.conf.remote_host,
                                                                    self.conf.remote_port,
                                                                    self.conf.unsolicited_bind_address,
                                                                    self.conf.unsolicited_bind_port,
                                                                    self.conf.unsolicited_timeout,
                                                                    self.logger)


    def _init_unix_sockets(self):
        self.logger.info('initiating UNIX socket for hostapd ctrl')
        self.request_sock = hostapd_ctrl.request_socket_unix(self.conf.unix_socket_path,
                                                             self.conf.request_timeout,
                                                             self.logger)
        self.unsolicited_sock = hostapd_ctrl.unsolicited_socket_unix(self.conf.unix_socket_path,
                                                                     self.conf.unsolicited_timeout,
                                                                     self.logger)
        self.logger.debug('initiated UNIX socket.')
