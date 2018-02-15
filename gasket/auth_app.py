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
from gasket.host import UnlearntUnauthenticatedHost
from gasket.port import Port
from gasket.datapath import Datapath

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
    # dp_name : Datapath
    macs = {}
    # mac : Host

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

            self.logger.info('Got %s work from queue ', type(work))
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

        dp_name = host_wi.dp_name
        dp_id = host_wi.dp_id
        mac = host_wi.mac
        ip = host_wi.ip
        vid = host_wi.vid
        port_no = host_wi.port
        self.logger.error('learning mac %s at port: %d' % (mac, port_no))
        if not mac in self.macs:
            self.logger.error('learning new host %s' % mac)
            self.macs[mac] = UnlearntUnauthenticatedHost(mac=mac, ip=ip,
                                                         logger=self.logger, rule_man=self.rule_man)

        host = self.macs[mac]

        self.logger.debug('size of dps: %d', len(self.dps))
        if not dp_name in self.dps:
            dp = Datapath(dp_id, dp_name)
            self.dps[dp_name] = dp
            self.logger.debug('added dp %s to dps', dp)

        dp = self.dps[dp_name]

        if not port_no in self.dps[dp_name].ports:
            self.logger.debug('adding port %s' % port_no)
            self.logger.error(self.config.dp_port_mode[dp_name]['interfaces'])
            conf_port = self.config.dp_port_mode[dp_name]['interfaces'].get(port_no, None)
            access_mode = None
            if conf_port:
                access_mode = conf_port['auth_mode']

            dp.add_port(Port(port_no, dp, access_mode))
        self.logger.error('before mac learned %s' % self.macs[mac])
        self.macs[mac] = self.macs[mac].learn(self.dps[dp_name].ports[port_no])
        self.logger.error('mac learned %s' % self.macs[mac])

    def _get_dp_name_and_port(self, mac):
        """Queries the prometheus faucet client,
         and returns the 'access port' that the mac address is connected on.
        Args:
             mac MAC address to find port for.
        Returns:
             dp name & port number.
        """
        # query faucets promethues.
        self.logger.info('querying prometheus')
        try:
            prom_mac_table = auth_app_utils.scrape_prometheus_vars(self.config.prom_url,
                                                                   ['learned_macs'])
        except Exception as e:
            self.logger.exception(e)
            return '', -1
        self.logger.info('queried prometheus. mac_table:\n%s\n',
                         prom_mac_table)
        ret_port = -1
        ret_dp_name = ""
        dp_port_mode = self.config.dp_port_mode
        for line in prom_mac_table:
            labels, float_as_mac = line.split(' ')
            macstr = auth_app_utils.float_to_mac(float_as_mac)
            self.logger.debug('float %s is mac %s', float_as_mac, macstr)
            if mac == macstr:
                # if this is also an access port, we have found the dpid and the port
                values = self.learned_macs_compiled_regex.match(labels)
                dpid, dp_name, n, port, vlan = values.groups()
                if dp_name in dp_port_mode and \
                        'interfaces' in dp_port_mode[dp_name] and \
                        int(port) in dp_port_mode[dp_name]['interfaces'] and \
                        'auth_mode' in dp_port_mode[dp_name]['interfaces'][int(port)] and \
                        dp_port_mode[dp_name]['interfaces'][int(port)]['auth_mode'] == 'access':
                    ret_port = int(port)
                    ret_dp_name = dp_name
                    break
        self.logger.info("name: %s port: %d", ret_dp_name, ret_port)
        return ret_dp_name, ret_port


    def authenticate(self, mac, user, acl_list):
        """Authenticates the user as specifed by adding ACL rules
        to the Faucet configuration file. Once added Faucet is signaled via SIGHUP.
        Args:
            mac (str): MAC Address.
            user (str): Username.
            acl_list (list of str): names of acls (in order of highest priority to lowest) to be applied.
        """
        self.logger.info("****authenticated: %s %s", mac, user)
        if not mac in self.macs:
            self.macs[mac] = UnlearntUnauthenticatedHost(mac=mac, logger=self.logger,
                                                         rule_man=self.rule_man)

        host = self.macs[mac]
        self.logger.error('authenticate host type: %s' % type(host))
        port = host.get_authing_learn_ports()
        self.logger.error('auth_port %s' % port)
        host = host.authenticate(user, port, acl_list)
        self.logger.error("type at end %s" % type(host))
        self.macs[mac] = host
        self.logger.error(self.macs)

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
        host = self.macs[mac]
        host.deauthenticate(None)
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
        self.logger.info('port status changed')
        dpid = port_change.dp_id
        port = port_change.port_no
        port_status = port_change.status
        dp_name = port_change.dp_name
        self.logger.info('DPID %d, Port %s has changed status: %d', dpid, port, port_status)
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
