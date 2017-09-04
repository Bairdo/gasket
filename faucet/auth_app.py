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

from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
# pytype: disable=pyi-error

from valve_util import get_logger
import config_parser
import config_parser_util
from auth_config import AuthConfig
import rule_manager
import auth_app_utils


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


class HTTPHandler(BaseHTTPRequestHandler):
    '''
    This class receives HTTP messages from the portal about
    the a change of state of the users.
    This could be either a log on or a log off of a user.
    The information is then passed on to rule_manager which
    installs/removes any appropriate rules.
    '''

    config = None
    rule_man = None
    logger = None
    logname = 'auth_app'
    def _set_headers(self, code, ctype):
        self.send_response(code)
        self.send_header('Content-type', ctype)
        self.end_headers()

    def _get_dp_name_and_port_from_intf(self, intf):
        d = self.config.intf_to_switch_port[intf]
        return d['switchname'], d['port']

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

    def do_POST(self):
        """Serves HTTP POST requests.
        Inherited from BaseHttpRequestHandler.
        """
        try:
            json_data = self.check_if_json()
            if json_data is None:
                return

            if self.path == self.config.dot1x_auth_path:
                self.authenticate(json_data)
            elif self.path == '/idle':
                self.logger.info('POST on /idle. Not supported')
                message = "idle not supported"
                self._set_headers(200, 'text/html')
                self.wfile.write(message.encode(encoding='utf-8'))
                self.log_message('%s', message)
            else:
                self.logger.info('POST on unkown path: %s' % self.path)
                self.send_error('Path not found\n')
        except Exception as e:
            self.logger.exception(e)

    def do_DELETE(self):
        """Serves HTTP DELETE requests.
        Inherited from BaseHttpRequestHandler.
        """
        json_data = self.check_if_json()
        if json_data is None:
            return

        if self.path == self.config.dot1x_auth_path:
            #check json has the right information
            if not ('mac' in json_data and 'user' in json_data):
                self.send_error('Invalid form\n')
                return
            self.deauthenticate(json_data['mac'], json_data['user'])
        else:
            self.send_error('Path not found\n')

    def authenticate(self, json_data):
        """Authenticates the user as specifed by json_data by adding ACL rules
        to the Faucet configuration file. Once added Faucet is signaled via SIGHUP.
        """
        self.logger.info(("****authenticated: {}".format(json_data)))
        conf_fd = None
        if self.path == self.config.dot1x_auth_path:  #request is for dot1xforwarder
            if not ('mac' in json_data and 'user' in json_data):
                self.send_error('Invalid form\n')
                return

            #valid request format so new user has authenticated
            mac = json_data['mac']
            user = json_data['user']
            intf = json_data['interface']
            switchname, switchport = self._get_dp_name_and_port_from_intf(intf)
            #switchname, switchport = self._get_dp_name_and_port(mac)

            if switchname == '' or switchport == -1:
                self.logger.warn(("Error switchname '{}' or switchport '{}' is unknown. Cannot generate acls for authed user '{}' on MAC '{}'".format(
                    switchname, switchport, user, mac)))
                #write response
                message = 'cant auth'
                # auth server doesnt handle errors at this stage so return 200
                self._set_headers(200, 'text/html')
                self.wfile.write(message.encode(encoding='utf-8'))
                self.log_message('%s', message)
                return

        message = 'authenticated new client({}) at MAC: {}\n'.format(
            user, mac)

        success = self.rule_man.authenticate(user, mac, switchname, switchport, logger=self.logger)

        self.logger.error(config_parser_util.read_config(self.config.acl_config_file, self.logname))

        # TODO probably shouldn't return success if the switch/port cannot be found.
        # but at this stage auth server (hostapd) can't do anything about it.
        # Perhaps look into the CoA radius thing, so that process looks like:
        #   - client 1x success, send to here.
        #   - can't find switch. return failure.
        #   - hostapd revokes auth, so now client is aware there was an error.
        #write response
        if success or not success:
            self._set_headers(200, 'text/html')
            self.wfile.write(message.encode(encoding='utf-8'))
            self.log_message('%s', message)

    def deauthenticate(self, mac, username):
        """Deauthenticates the mac and username by removing related acl rules
        from Faucet's config file.
        Args:
            mac (str): mac address string to deauth
            username (str): username to deauth.
        """
        self.logger.info('---deauthenticated: {} {}'.format(mac, username))

        success = self.rule_man.deauthenticate(username, mac, logger=self.logger)
        # TODO possibly handle success somehow. However the client wpa_supplicant, etc,
        # will likley think it has logged off, so is there anything we can do from hostapd to
        # say they have not actually logged off.
        # EAP LOGOFF is a one way message (not ack=ed)
        if success or not success:
            self._set_headers(200, 'text/html')
            message = 'deauthenticated client {} at {} \n'.format(username, mac)
            self.wfile.write(message.encode(encoding='utf-8'))
            self.log_message('%s', message)

    def check_if_json(self):
        """Check if HTTP content is json.
        Returns:
            json object if json, otherwise None.
        """
        try:
            ctype, pdict = cgi.parse_header(
                self.headers.get('content-type'))
        except:
            self.send_error('No content-type header\n')
            return None

        if ctype != 'application/json':
            self.send_error('Data is not a JSON object\n')
            return None
        content_length = int(self.headers.get('content-length'))
        try:
            data = self.rfile.read(content_length).decode('utf-8')
        except UnicodeDecodeError:
            data = self.rfile.read(content_length)
            self.logger.warn('UnicodeDecodeError %s' % data)
        try:
            json_data = json.loads(data)
        except ValueError:
            self.send_error('Not JSON object\n')
            return None

        return json_data

    def send_error(self, error):
        """Sends an 404. and logs error.
        Args:
            error: error to log
        """
        # TODO do we want to actually send the error message back perhaps?
        self._set_headers(404, 'text/html')
        self.log_message('Error: %s', error)
        self.wfile.write(error.encode(encoding='utf_8'))

    do_GET = do_POST


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', help='location of yaml configuration file')
    args = parser.parse_args()
    config_filename = args.config
    conf = AuthConfig(config_filename)
    logger = get_logger('httpserver', conf.logger_location, logging.DEBUG, 1)
    HTTPHandler.logger = logger
    HTTPHandler.config = conf
    HTTPHandler.rule_man = rule_manager.RuleManager(conf)
    server = ThreadedHTTPServer(('', conf.listen_port), HTTPHandler)
    logger.info(('starting server %d', conf.listen_port))
    server.serve_forever()

