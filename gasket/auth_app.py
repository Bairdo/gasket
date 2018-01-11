"""This is the controller side authentication app.
It communicates with an authentication server (hostapd, captive portal) via HTTP.
And with rule_manager which communicates with Faucet via changing the Faucet configuration file,
and sending it a SIGHUP.
"""
# pylint: disable=import-error

import argparse
import logging
import os
import re
import signal
import socket
import sys

from ryu.base import app_manager
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import dpset
from ryu.controller import ofp_event
from ryu.lib import hub

import faucet.valve_of as valve_of
from gasket.auth_config import AuthConfig
from gasket import rule_manager
from gasket import auth_app_utils
from gasket import hostapd_ctrl

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
FAUCET_ENTERPRISE_NUMBER = 12345
FAUCET_RADIUS_ATTRIBUTE_ACL_TYPE = 1

class AuthApp(app_manager.RyuApp):
    '''
    This class recieves messages hostapd_ctrl from the portal via
    UNIX DOMAIN sockets, about the a change of state of the users.
    This could be either a log on or a log off of a user.
    The information is then passed on to rule_manager which
    installs/removes any appropriate rules.
    '''

    OFP_VERSIONS = valve_of.OFP_VERSIONS
    _CONTEXTS = {'dpset': dpset.DPSet}

    config = None
    rule_man = None
    logger = None
    logname = 'auth_app'

    hapd_req = None
    hapd_unsolicited = None

    def __init__(self, *args, **kwargs):
        super(AuthApp, self).__init__(*args, **kwargs)
        config_filename = os.getenv('GASKET_CONFIG', '/etc/ryu/faucet/gasket/auth.yaml')
        self.config = AuthConfig(config_filename)
        self.logger = auth_app_utils.get_logger('auth_app', self.config.logger_location, logging.DEBUG, 1)
        self.rule_man = rule_manager.RuleManager(self.config, self.logger)

    def _init_sockets(self):
        self._init_request_socket()
        self._init_unsolicited_socket()

    def _init_unsolicited_socket(self):
        if self.config.hostapd_socket_path:
            self.logger.info('using unix socket for hostapd ctrl')
            self.hapd_unsolicited = hostapd_ctrl.unsolicited_socket_unix(
                self.config.hostapd_socket_path, self.logger)
        else:
            self.logger.info('using UDP socket for hostapd ctrl')
            self.hapd_unsolicited = hostapd_ctrl.unsolicited_socket_udp(
                self.config.hostapd_host, self.config.hostapd_port, self.logger)

    def _init_request_socket(self):
        if self.config.hostapd_socket_path:
            self.logger.info('using unix socket for hostapd ctrl')
            self.hapd_req = hostapd_ctrl.request_socket_unix(
                self.config.hostapd_socket_path, self.logger)
        else:
            self.logger.info('using UDP socket for hostapd ctrl')
            self.hapd_req = hostapd_ctrl.request_socket_udp(
                self.config.hostapd_host, self.config.hostapd_port, self.logger)

    def start(self):
        super(AuthApp, self).start()
        self.logger.info('Starting threads')
        print('starting thread')
        self.threads.extend([
                        hub.spawn(thread) for thread in ( self.run, )])

        signal.signal(signal.SIGINT, self._handle_sigint)

    def run(self):
        """Main loop, waits for messages from hostapd ctl socket,
        and processes them.
        """
        self.logger.info('initiating sockets')
        self._init_sockets()
        self.logger.info('sockets initiated')
        while True:
            self.logger.info('waiting for receive')
            try:
                data = str(self.hapd_unsolicited.receive())
                if 'CTRL-EVENT-EAP-SUCCESS' in data:
                    self.logger.info('success message')
                    mac = data.split()[1].replace("'", '')
                    sta = self.hapd_req.get_sta(mac)
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
                    self.authenticate(mac, username, radius_acl_list)
                elif 'AP-STA-DISCONNECTED' in data:
                    self.logger.info('%s disconnected message', data)
                    mac = data.split()[1].replace("'", '')
                    self.deauthenticate(mac)
                else:
                    self.logger.info('unknown message %s', data)
            except socket.timeout:
                if not self.hapd_unsolicited.ping():
                    self.logger.warn('no pong received from unsolicited socket')
                    self.hapd_unsolicited.close()
                    self._init_unsolicited_socket()
                if not self.hapd_req.ping():
                    self.logger.warn('no pong received from request (solicited) socket')
                    self.hapd_req.close()
                    self._init_request_socket()

    def _get_dp_name_and_port(self, mac):
        """Queries the prometheus faucet client,
         and returns the 'access port' that the mac address is connected on.
        Args:
             mac MAC address to find port for.
        Returns:
             dp name & port number.
        """
        # query faucets promethues.
        prom_mac_table, prom_name_dpid = auth_app_utils.scrape_prometheus_vars(self.config.prom_url, ['learned_macs', 'faucet_config_dp_name'])

        dpid_name = auth_app_utils.dpid_name_to_map(prom_name_dpid)
        self.logger.debug(dpid_name)

        ret_port = -1
        ret_dp_name = ""
        dp_port_mode = self.config.dp_port_mode
        for line in prom_mac_table:
            labels, float_as_mac = line.split(' ')
            macstr = auth_app_utils.float_to_mac(float_as_mac)
            self.logger.debug('float %s is mac %s', float_as_mac, macstr)
            if mac == macstr:
                # if this is also an access port, we have found the dpid and the port
                _, _, dpid, _, n, _, port, _, vlan, _ = re.split(r'\W+', labels)
                dp_name = dpid_name[dpid]
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

        switchname, switchport = self._get_dp_name_and_port(mac)

        if switchname == '' or switchport == -1:
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
        if not success:
            # TODO one or the other?
            self.hapd_req.deauthenticate(mac)
            self.hapd_req.disassociate(mac)

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

    def is_port_managed(self, dpid, port_num):
        """
        Args:
            dpid (int): datapath id.
            port_num (int): port number.
        Returns:
            datapath name (str) if this dpid & port combo are managed (provide authentication). otherwise None
        """
        # query prometheus for the dpid -> name.
        # use the name to look in auth.yaml for the datapath.
        # if the dp is there, then use the port.
        #    if the port is there and it is set to 'access' return true
        # otherwise return false.
        dp_names = auth_app_utils.scrape_prometheus_vars(self.config.prom_url, ['faucet_config_dp_name'])[0]
        dp_name = ''
        for l in dp_names:
            pattern = r'name="(.*)"}} {0}\.0'.format(dpid)
            m = re.search(pattern, l)
            if m:
                dp_name = m.groups()[0]
                break

        if dp_name in self.config.dp_port_mode:
            if port_num in self.config.dp_port_mode[dp_name]['interfaces']:
                if 'auth_mode' in self.config.dp_port_mode[dp_name]['interfaces'][port_num]:
                    mode = self.config.dp_port_mode[dp_name]['interfaces'][port_num]['auth_mode']
                    if mode == 'access':
                        return dp_name
        return None

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER) # pylint: disable=no-member
    def port_status_handler(self, ryu_event):
        """Deauthenticates all hosts on a port if the port has gone down.
        """
        msg = ryu_event.msg
        ryu_dp = msg.datapath
        dpid = ryu_dp.id
        port = msg.desc.port_no

        port_status = msg.desc.state & msg.datapath.ofproto.OFPPS_LINK_DOWN
        self.logger.info('DPID %d, Port %d has changed status: %d', dpid, port, port_status)
        if port_status == 1: # port is down
            dp_name = self.is_port_managed(dpid, port)
            self.logger.debug('dp_name: %s', dp_name)
            if dp_name:
                removed_macs = self.rule_man.reset_port_acl(dp_name, port)
                self.logger.info('removed macs: %s', removed_macs)
                for mac in removed_macs:
                    self.logger.info('sending deauth for %s' % mac)
                    self.hapd_req.deauthenticate(mac)

                self.logger.debug('reset port completed')

    def _handle_sigint(self, sigid, frame):
        """Handles the SIGINT signal.
        Closes the hostapd control interfaces, and kills the main thread ('self.run').
        """
        self.logger.info('SIGINT Received - closing hostapd sockets')
        self.hapd_req.close()
        self.hapd_unsolicited.close()
        self.logger.info('hostapd sockets closed')
        self.logger.info('Killing threads ...')
        for t in self.threads:
            t.kill()
        self.logger.info('Threads killed')
        sys.exit()

