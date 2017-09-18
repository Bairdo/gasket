"""This is the controller side authentication app.
It communicates with an authentication server (hostapd, captive portal) via HTTP.
And with rule_manager which communicates with Faucet via changing the Faucet configuration file,
and sending it a SIGHUP.
"""
# pylint: disable=import-error

import argparse
import cgi
import json
import logging
import os
import re
import threading
import time

from valve_util import get_logger
import config_parser
import config_parser_util
from auth_config import AuthConfig
import rule_manager
import auth_app_utils
import hostapd_ctrl

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

    hapd_req = None
    hapd_unsolicited = None

    def __init__(self, args):

        config_filename = args.config
        self.config = AuthConfig(config_filename)
        self.logger = get_logger('auth_app', self.config.logger_location, logging.DEBUG, 1)
        self.rule_man = rule_manager.RuleManager(self.config, self.logger)

        if self.config.hostapd_socket_path:
            self.logger.info('using unix socket for hostapd ctrl')
            self.hapd_req = hostapd_ctrl.request_socket_unix(self.config.hostapd_socket_path, self.logger)
            self.hapd_unsolicited = hostapd_ctrl.unsolicited_socket_unix(self.config.hostapd_socket_path, self.logger)
        else:
            self.logger.info('using UDP socket for hostapd ctrl')
            self.hapd_req = hostapd_ctrl.request_socket_udp(self.config.hostapd_host, self.config.hostapd_port, self.logger)
            self.hapd_unsolicited = hostapd_ctrl.unsolicited_socket_udp(self.config.hostapd_host, self.config.hostapd_port, self.logger)

    def run(self):
        while True:
            self.logger.info('waiting for receive')
            d = str(self.hapd_unsolicited.receive())
            if 'CTRL-EVENT-EAP-SUCCESS' in d:
                self.logger.info('success message')
                mac = d.split()[1].replace("'",'')
                sta = self.hapd_req.get_sta(mac)
                self.authenticate(mac, sta['dot1xAuthSessionUserName'])
            elif 'AP-STA-DISCONNECTED' in d:
                self.logger.info('%s disconnected message' % d)
                mac = d.split()[1].replace("'",'')
                self.deauthenticate(mac)
            else:
                self.logger.info('unknown message %s' % d)

    def auth_callback(self):
        pass


    def _get_dp_name_and_port(self, mac):
        """Queries the prometheus faucet client,
         and returns the 'access port' that the mac address is connected on.
        Args:
             mac MAC address to find port for.
        Returns:
             dp name & port number.
        """
        # query faucets promethues.
        prom_txt = auth_app_utils.scrape_prometheus(self.config.prom_url)

        prom_mac_table = []
        prom_name_dpid = []
        prom_dpid_port_mode = []
        for line in prom_txt.splitlines():
            self.logger.info(line)
            if line.startswith('learned_macs'):
                prom_mac_table.append(line)
            if line.startswith('faucet_config_dp_name'):
                prom_name_dpid.append(line)

        dpid_name = auth_app_utils.dpid_name_to_map(prom_name_dpid)

        ret_port = -1
        ret_dp_name = ""
        for line in prom_mac_table:
            labels, float_as_mac = line.split(' ')
            if mac == auth_app_utils.float_to_mac(float_as_mac):
                # if this is also an access port, we have found the dpid and the port
                _, _, dpid, _, n, _, port, _, vlan, _ = re.split(r'\W+', labels)
                dp_name = dpid_name[dpid]
                if dp_name in self.config.dp_port_mode and \
                        'interfaces' in self.config.dp_port_mode[dp_name] and \
                        int(port) in self.config.dp_port_mode[dp_name]['interfaces'] and \
                        'auth_mode' in self.config.dp_port_mode[dp_name]['interfaces'][int(port)] and \
                        self.config.dp_port_mode[dp_name]['interfaces'][int(port)]['auth_mode'] == 'access':
                    ret_port = int(port)
                    ret_dp_name = dp_name
                    break
        self.logger.info(("name: {} port: {}".format(ret_dp_name, ret_port)))
        return ret_dp_name, ret_port

    def authenticate(self, mac, user, intf=None):
        """Authenticates the user as specifed by adding ACL rules
        to the Faucet configuration file. Once added Faucet is signaled via SIGHUP.
        """
        self.logger.info(("****authenticated: {} {}".format(mac, user)))

        switchname, switchport = self._get_dp_name_and_port(mac)

        if switchname == '' or switchport == -1:
            self.logger.warn(("Error switchname '{}' or switchport '{}' is unknown. Cannot generate acls for authed user '{}' on MAC '{}'".format(
                switchname, switchport, user, mac))) 
            # TODO one or the other?
            self.hapd_req.deauthenticate(mac)
            self.hapd_req.disassociate(mac)

        success = self.rule_man.authenticate(user, mac, switchname, switchport)

        self.logger.error(config_parser_util.read_config(self.config.acl_config_file, self.logname))

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
        self.logger.info('---deauthenticated: {} {}'.format(mac, username))

        success = self.rule_man.deauthenticate(username, mac)
        # TODO possibly handle success somehow. However the client wpa_supplicant, etc,
        # will likley think it has logged off, so is there anything we can do from hostapd to
        # say they have not actually logged off.
        # EAP LOGOFF is a one way message (not ack-ed)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', help='location of yaml configuration file')
    args = parser.parse_args()
    auth_app = AuthApp(args)
    auth_app.run()


