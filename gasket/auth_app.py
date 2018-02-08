"""This is the controller side authentication app.
It communicates with an authentication server (hostapd, captive portal) via HTTP.
And with rule_manager which communicates with Faucet via changing the Faucet configuration file,
and sending it a SIGHUP.
"""
# pylint: disable=import-error

import argparse
import logging
import queue
import re
import signal
import sys

from gasket.auth_config import AuthConfig
from gasket import rule_manager
from gasket import auth_app_utils
from gasket.hostapd_conf import HostapdConf
from gasket import hostapd_socket_thread
from gasket import work_item
from gasket import rabbitmq
from gasket import host

class Proto(object):
    """Class for protocol constants.
    """
    ETHER_ARP = 0x0806
    ETHER_IPv4 = 0x0800
    ETHER_IPv6 = 0x86DD
    ETHER_EAPOL = 0x888E
    IP_TCP = 6
    IP_UDP = 17
    DHCP_CLIENT_PORT = 68
    DHCP_SERVER_PORT = 67
    DNS_PORT = 53
    HTTP_PORT = 80


LEARNED_MACS_REGEX = r"""learned_macs{dp_id="(0x[a-f0-9]+)",dp_name="([\w-]+)",n="(\d+)",port="(\d+)",vlan="(\d+)"}"""


class AuthApp(object):
    '''
    This class recieves messages hostapd_ctrl from the portal via
    UNIX DOMAIN sockets, about the a change of state of the users.
    This could be either a log on or a log off of a user.
    The information is then passed on to rule_manager which
    installs/removes any appropriate rules.
    '''


    config = None
    rule_man = None
    logger = None
    logname = 'auth_app'

    work_queue = None
    threads = []

    dps = {}
    macs = {}

    def __init__(self, config, logger):
        super(AuthApp, self).__init__()
        self.config = config
        self.logger = logger
        self.rule_man = rule_manager.RuleManager(self.config, self.logger)
        self.learned_macs_compiled_regex = re.compile(LEARNED_MACS_REGEX)
        self.work_queue = queue.Queue()


    def start(self):
        """Starts separate thread for each hostapd socket.
        And runs as the worker thread processing the (de)authentications/.

        Main Worker thread.
        """
        signal.signal(signal.SIGINT, self._handle_sigint)

        self.logger.info('Starting hostapd socket threads')
        print('Starting hostapd socket threads ...')

        for hostapd_name, conf in self.config.hostapds.items():
            hostapd_conf = HostapdConf(hostapd_name, conf)
            hst = hostapd_socket_thread.HostapdSocketThread(hostapd_conf, self.work_queue,
                                                            self.config.logger_location)
            self.logger.info('Starting thread %s', hst)
            hst.start()
            self.threads.append(hst)
            self.logger.info('Thread running')

        rt = rabbitmq.RabbitMQ(self.work_queue, self.config.logger_location)
        try:
            rt.start()
            self.threads.append(rt)
        except Exception as e:
            self.logger.exception(e)

        print('Started socket Threads.')
        self.logger.info('Starting worker thread.')
        while True:
            work = self.work_queue.get()

            self.logger.info('Got work from queue')
            if isinstance(work, work_item.AuthWorkItem):
                self.authenticate(work.mac, work.username, work.acllist)
            elif isinstance(work, work_item.DeauthWorkItem):
                self.deauthenticate(work.mac)
            elif isinstance(work, work_item.L2LearnWorkItem):
                self.l2learn(work)
            elif isinstance(work, work_item.PortChangeWorkItem):
                self.port_status_handler(work)
            else:
                self.logger.warn("Unsupported WorkItem type: %s", type(work))

    def l2learn(self, host_wi):
        # TODO support case where host being learnt is already authenticated.
        h = host.Host(host_wi.mac, host_wi.ip, host_wi.dp_name, host_wi.dp_id, host_wi.port, host_wi.vid)
        self.macs[host_wi.mac] = h
        if not host_wi.dp_name in self.dps:
            self.dps[host_wi.dp_name] = {}
        self.dps[host_wi.dp_name][host_wi.port] = h

    def authenticate(self, mac, user, acl_list):
        """Authenticates the user as specifed by adding ACL rules
        to the Faucet configuration file. Once added Faucet is signaled via SIGHUP.
        Args:
            mac (str): MAC Address.
            user (str): Username.
            acl_list (list of str): names of acls (in order of highest priority to lowest) to be applied.
        """
        self.logger.info("****authenticated: %s %s", mac, user)

        host = self.macs[mac]

        host.username = user
        host.acl_list = acl_list

        switchname = host.dp_name
        switchport = host.port
        if switchname is None  or switchport == -1:
            self.logger.warn(
                "Error switchname '%s' or switchport '%d' is unknown. Cannot generate acls for authed user '%s' on MAC '%s'",
                switchname, switchport, user, mac)
            # TODO one or the other?
#            self.hapd_req.deauthenticate(mac)
#            self.hapd_req.disassociate(mac)
            return

        self.logger.info('found mac')

        success = self.rule_man.authenticate(user, mac, switchname, switchport, acl_list)

        # TODO probably shouldn't return success if the switch/port cannot be found.
        # but at this stage auth server (hostapd) can't do anything about it.
        # Perhaps look into the CoA radius thing, so that process looks like:
        #   - client 1x success, send to here.
        #   - can't find switch. return failure.
        #   - hostapd revokes auth, so now client is aware there was an error.
#        if not success:
            # TODO one or the other?
#            self.hapd_req.deauthenticate(mac)
#            self.hapd_req.disassociate(mac)

    def deauthenticate(self, mac, username=None):
        """Deauthenticates the mac and username by removing related acl rules
        from Faucet's config file.
        Args:
            mac (str): mac address string to deauth
            username (str): username to deauth.
        """
        self.logger.info('---deauthenticated: %s %s', mac, username)

        self.rule_man.deauthenticate(username, mac)
        # TODO possibly handle success somehow. However the client wpa_supplicant, etc,
        # will likley think it has logged off, so is there anything we can do from hostapd to
        # say they have not actually logged off.
        # EAP LOGOFF is a one way message (not ack-ed)

    def is_port_managed(self, dp_name, port_num):
        """
        Args:
            dp_name (str): datapath name.
            port_num (int): port number.
        Returns:
            bool - True if this dpid & port combo are managed (provide authentication).
             otherwise False
        """
        if dp_name in self.config.dp_port_mode:
            if port_num in self.config.dp_port_mode[dp_name]['interfaces']:
                if 'auth_mode' in self.config.dp_port_mode[dp_name]['interfaces'][port_num]:
                    mode = self.config.dp_port_mode[dp_name]['interfaces'][port_num]['auth_mode']
                    if mode == 'access':
                        return True
        return False

    def port_status_handler(self, port_change):
        """Deauthenticates all hosts on a port if the port has gone down.
        """
        dpid = port_change.dp_id
        port = port_change.port_no
        port_status = port_change.status
        dp_name = port_change.dp_name
        self.logger.info('DPID %d, Port %d has changed status: %d', dpid, port, port_status)
        if port_status == 1: # port is down
            if self.is_port_managed(dp_name, port):
                self.logger.debug('DP %s is mananged.', dp_name)
                removed_macs = self.rule_man.reset_port_acl(dp_name, port)
                self.logger.info('removed macs: %s', removed_macs)
                for mac in removed_macs:
                    self.logger.info('sending deauth for %s', mac)
#                    self.hapd_req.deauthenticate(mac)

                self.logger.debug('reset port completed')

    def _handle_sigint(self, sigid, frame):
        """Handles the SIGINT signal.
        Closes the hostapd control interfaces, and kills the main thread ('self.run').
        """
        self.logger.info('SIGINT Received - Killing hostapd socket threads ...')
        for t in self.threads:
            t.kill()
        self.logger.info('Threads killed')
        sys.exit()


if __name__ == "__main__":
    print('Parsing args ...')
    parser = argparse.ArgumentParser()
    parser.add_argument('config', metavar='config', type=str,
                        nargs=1, help='path to configuration file')
    args = parser.parse_args()
    config_filename = '/etc/ryu/faucet/gasket/auth.yaml'
    if args.config:
        config_filename = args.config[0]
    print('Loading config %s' % config_filename)
    auth_config = AuthConfig(config_filename)
    log = auth_app_utils.get_logger('auth_app', auth_config.logger_location, logging.DEBUG, 1)

    aa = AuthApp(auth_config, log)
    print('Running AuthApp')
    try:
        aa.start()
    except Exception as e:
        log.exception(e)
