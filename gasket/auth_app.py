"""This is the controller side authentication app.
It communicates with an authentication server (hostapd, captive portal) via HTTP.
And with rule_manager which communicates with Faucet via changing the Faucet configuration file,
and sending it a SIGHUP.
"""
# pylint: disable=import-error

import argparse
from datetime import datetime
import queue
import re
import signal
import sys

from gasket.auth_config import AuthConfig
from gasket import auth_app_utils
from gasket import config_parser
from gasket import hostapd_socket_thread
from gasket import rabbitmq
from gasket import rule_manager
from gasket import work_item
from gasket.host import UnlearntUnauthenticatedHost
from gasket.port import Port
from gasket.datapath import Datapath
from gasket import prometheus_thread


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
    hostapds = {}
    # hostapd_name : HostapdConf

    def __init__(self, config, logger):
        super(AuthApp, self).__init__()
        self.config = config

        # TODO replace the AuthConfig with the faucet conf class style.
        # this is just hack until it is all complete.
        temp_config = {}
        temp_config['hostapds'] = config.hostapds
        temp_config['dps'] = config.dps
        self.dps, self.hostapds = config_parser.parse_config(temp_config)

        self.logger = logger
        self.rule_man = rule_manager.RuleManager(self.config, self.logger)
        self.work_queue = queue.Queue()
        self.setup_datapath()

    def start(self):
        """Starts separate thread for each hostapd socket.
        And runs as the worker thread processing the (de)authentications/.

        Main Worker thread.
        """
        signal.signal(signal.SIGINT, self._handle_sigint)

        self.logger.info('Starting hostapd socket threads')
        print('Starting hostapd socket threads ...')

        for hostapd_conf in self.hostapds.values():
            hst = hostapd_socket_thread.HostapdSocketThread(hostapd_conf, self.work_queue,
                                                            self.config.logger_location)
            self.logger.info('Starting thread %s', hst)
            hst.start()
            self.threads.append(hst)
            self.logger.info('Thread running')

        dp_ids = []
        for dp in self.dps.values():
            dp_ids.append(dp.dp_id)
        rt = rabbitmq.RabbitMQ(dp_ids, self.work_queue, self.config.logger_location, self.config.rabbit_host, self.config.rabbit_port)
        try:
            rt.start()
            self.threads.append(rt)
        except Exception as e:
            self.logger.exception(e)

        pt = prometheus_thread.Prometheus(self.work_queue, self.config.logger_location, self.config.prom_url, self.config.prom_port, self.config.prom_sleep)
        try:
            pt.start()
            self.threads.append(pt)
        except Exception as e:
            self.logger.exception(e)

        print('Started socket Threads.')
        print('Working')
        self.logger.info('Working worker thread.')
        while True:
            work_list = []
            auth_count = 0
            deauth_count = 0
            l2learn_count = 0
            port_status_count = 0
            work_list.append(self.work_queue.get())
            start_time = datetime.now()
            while not self.work_queue.empty():
                work_list.append(self.work_queue.get())
            self.rule_man.read_base(self.config.base_filename)
            for work in work_list:
                try:
                    self.logger.info('Got %s work from queue ', type(work))
                    if isinstance(work, work_item.AuthWorkItem):
                        self.authenticate(work.mac, work.username, work.acllist, work.hostapd_name, work.creation_time)
                        auth_count += 1
                    elif isinstance(work, work_item.DeauthWorkItem):
                        self.deauthenticate(work.mac, work.hostapd_name)
                        deauth_count += 1
                    elif isinstance(work, work_item.L2LearnWorkItem):
                        self.l2learn(work)
                        l2learn_count += 1
                    elif isinstance(work, work_item.PortChangeWorkItem):
                        self.port_status_handler(work)
                        port_status_count += 1
                    else:
                        self.logger.warn("Unsupported WorkItem type: %s", type(work))
                except Exception as e:
                    # Hope that things are still in a constient state and try the next work
                    self.logger.exception(e)
            self.rule_man.write_base(self.config.base_filename)
            self.rule_man.translate_to_faucet()
            end_time = datetime.now()

            total_time = auth_app_utils.time_difference(start_time, end_time)
            self.logger.info('processed %d workitems a: %d, d: %d, l2: %d, p: %d in time: %d' % (len(work_list), auth_count,
                                                                                                 deauth_count, l2learn_count,
                                                                                                 port_status_count, total_time))

    def setup_datapath(self):
        """Builds the datpath/ports this instance of gasket is aware of.
        """
        for dp_name, datapath in self.config.dps.items():
            dp_id = datapath['dp_id']
            if not dp_name in self.dps:
                dp = Datapath(dp_id, dp_name)
                self.dps[dp_name] = dp
                self.logger.debug('added dp %s to dps', dp)

            dp = self.dps[dp_name]
            for port_no, conf_port in datapath['interfaces'].items():
                if not port_no in self.dps[dp_name].ports:
                    self.logger.debug('adding port %s' % port_no)
                    access_mode = None
                    if conf_port:
                        access_mode = conf_port.get('auth_mode', None)

                    dp.add_port(Port(port_no, dp, access_mode))

    def l2learn(self, host_wi):
        """Learns a host, if host is already authenticated rules are applied.
        Args:
            host_wi (work_item.L2LearnWorkItem): the host to learn
        """
        dp_name = host_wi.dp_name
        mac = host_wi.mac
        ip = host_wi.ip
        port_no = host_wi.port
        self.logger.info('learning mac %s at dp: %s port: %d', mac, dp_name, port_no)
        if not mac in self.macs:
            self.logger.info('learning new host %s', mac)
            self.macs[mac] = UnlearntUnauthenticatedHost(mac=mac, ip=ip,
                                                         logger=self.logger, rule_man=self.rule_man)

        self.macs[mac] = self.macs[mac].learn(self.dps[dp_name].ports[port_no])

    def authenticate(self, mac, user, acl_list, hostapd_name, start_time):
        """Authenticates the user as specifed by adding ACL rules
        to the Faucet configuration file. Once added Faucet is signaled via SIGHUP.
        Args:
            mac (str): MAC Address.
            user (str): Username.
            acl_list (list of str): names of acls (in order of highest priority to lowest) to be applied.
            hostapd_name (str): name of the hostapd that did the auth.
        """
        auth_start_time = datetime.now()
        if not mac in self.macs:
            self.macs[mac] = UnlearntUnauthenticatedHost(mac=mac, logger=self.logger,
                                                         rule_man=self.rule_man)

        host = self.macs[mac]
        self.logger.info("authenticating: %s %s %s", type(host), mac, user)
        port = host.get_authing_learn_ports()
        hapd = self.hostapds[hostapd_name]

        # if only one port, must be located on that port.
        # otherwise we use the last learnt auth port
        if len(hapd.ports) == 1:
            port = next(iter(hapd.ports.values()))
            host = self.macs[mac].learn(port)

        host = host.authenticate(user, port, acl_list)
        self.macs[mac] = host
        self.logger.info('authenticate complete %s' % mac)
        end_time = datetime.now()

        total_time = auth_app_utils.time_difference(start_time, end_time)
        auth_time = auth_app_utils.time_difference(auth_start_time, end_time)

        self.logger.info('time (spent actually processing (not in queue)) to authenticate mac: %s %dms' % (mac, auth_time))
        self.logger.info('time (since event received) to authenticate mac: %s %dms' % (mac, total_time))
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

    def deauthenticate(self, mac, hostapd_name, username=None):
        """Deauthenticates the mac and username by removing related acl rules
        from Faucet's config file.
        Args:
            mac (str): mac address string to deauth
            username (str): username to deauth.
            hostapd_name (str): name of the hostapd that did the deauth.
        """
        self.logger.info('deauthenticating: %s %s', mac, username)
        host = self.macs.get(mac, None)
        if host:
            self.macs[mac] = host.deauthenticate(None)
        self.logger.info('deauthenticate complete')
        # TODO possibly handle success somehow. However the client wpa_supplicant, etc,
        # will likley think it has logged off, so is there anything we can do from hostapd to
        # say they have not actually logged off.
        # EAP LOGOFF is a one way message (not ack-ed)

    def port_status_handler(self, port_change):
        """Deauthenticates all hosts on a port if the port has gone down.
        """
        dpid = port_change.dp_id
        port_no = port_change.port_no
        port_status = port_change.status
        dp_name = port_change.dp_name
        self.logger.info('DPID %d, Port %s has changed status: %d', dpid, port_no, port_status)
        if not port_status: # port is down
            port = self.dps[dp_name].ports[port_no]
            if port.auth_mode == 'access':
                self.logger.debug('DP %s is mananged.', dp_name)
                for mac in list(port.authed_hosts):
                    self.logger.debug('mac: %s deauthed via port down' % mac)
                    self.macs[mac] = self.macs[mac].deauthenticate(port)
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
    config_filename = '/etc/faucet/gasket/auth.yaml'
    if args.config:
        config_filename = args.config[0]
    print('Loading config %s' % config_filename)
    auth_config = AuthConfig(config_filename)
    log = auth_app_utils.get_logger('auth_app', auth_config.logger_location, auth_config.logger_level, 1)

    aa = AuthApp(auth_config, log)
    print('Running AuthApp')
    try:
        aa.start()
    except Exception as e:
        log.exception(e)
