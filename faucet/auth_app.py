"""This is the controller side authentication app.
It communicates with an authentication server (hostapd, captive portal) via HTTP.
And with Faucet via changing the Faucet configuration file, and sending it a SIGHUP.
"""
# pylint: disable=import-error

import argparse
import cgi
import json
import logging
import os
import re
import signal
import threading

from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

import requests

from valve_util import get_logger
import config_parser
import my_lockfile as lockfile
from auth_config import AuthConfig
import rule_generator

import auth_app_utils

THREAD_LOCK = threading.Lock()


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
    The information is then passed to the controller by
    modifying configuration files as well as sending a signal to it.
    '''

    config = None
    rule_gen = None
    logger = None
    def _set_headers(self, code, ctype):
        self.send_response(code)
        self.send_header('Content-type', ctype)
        self.end_headers()

    def scrape_prometheus(self):
        """Query prometheus specified by config. Removes comment lines.
        Returns:
            string containing all prometheus variables without comments.
        """
        prom_url = self.config.prom_url
        prom_vars = []
        for prom_line in requests.get(prom_url).text.split('\n'):
            if not prom_line.startswith('#'):
                prom_vars.append(prom_line)
        return '\n'.join(prom_vars)

    def _get_dp_name_and_port(self, mac):
        """Queries the prometheus faucet client,
         and returns the 'access port' that the mac address is connected on.
        Args:
             mac MAC address to find port for.
        Returns:
             dp name & port number.
        """
        # query faucets promethues.
        prom_txt = self.scrape_prometheus()

        prom_mac_table = []
        prom_name_dpid = []
        prom_dpid_port_mode = []
        for line in prom_txt.splitlines():
            self.logger.info(line)
            if line.startswith('learned_macs'):
                prom_mac_table.append(line)
            if line.startswith('faucet_config_dp_name'):
                prom_name_dpid.append(line)
            if line.startswith('dp_port_mode'):
                prom_dpid_port_mode.append(line)

        dpid_name = auth_app_utils.dpid_name_to_map(prom_name_dpid)
        dp_port_mode = auth_app_utils.dp_port_mode_to_map(prom_dpid_port_mode)

        ret_port = -1
        ret_dp_name = ""
        for line in prom_mac_table:
            labels, float_as_mac = line.split(' ')
            if mac == auth_app_utils.float_to_mac(float_as_mac):
                # if this is also an access port, we have found the dpid and the port
                _, _, dpid, _, n, _, port, _, vlan, _ = re.split(r'\W+', labels)
                if dpid in dp_port_mode and \
                        port in dp_port_mode[dpid] and \
                        dp_port_mode[dpid][port] == 'access':
                    ret_port = int(port)
                    ret_dp_name = dpid_name[dpid]
                    break
        self.logger.info(("name: {} port: {}".format(ret_dp_name, ret_port)))
        return ret_dp_name, ret_port

    def remove_acls_startswith(self, mac, name, switchname, switchport):
        """Helper function for self.remove_acls(), but passes startswith=True,
             so that the name field will be compared using string.startswith,
             instead of equality.
        """
        self.remove_acls(mac, name, switchname, switchport, startswith=True)

    def remove_acls(self, mac, name, switchname, switchport, startswith=False):
        """Removes the ACLS for the mac and name from the config file.
        NOTE: only from the port that the mac address is authenticated on, currently.
        Args:
            mac: mac address of authenticated user
            name: the 'name' field of the acl rule in faucet.yaml,
                 generally username or captiveportal_*
            startswith: Boolean value, should name field be compared using string.startswith(),
                or == equality
        """

        # TODO remove rules from any port acl.
        # load faucet.yaml and its included yamls
        # TODO this method name does not match what it actually does.
        all_acls = config_parser.load_acls(self.config.acl_config_file)

        aclname = 'port_' + switchname + '_' + str(switchport)
        port_acl = all_acls['acls'][aclname]
        i = 0
        updated_port_acl = []
        for rule in port_acl:
            try:
                if rule['rule']['_mac_'] is not None and rule['rule']['_name_'] is not None:
                    if startswith and rule['rule']['_mac_'] == mac \
                         and rule['rule']['_name_'].startswith(name):
                        continue
                    if rule['rule']['_mac_'] == mac and rule['rule']['_name_'] == name:
                        continue
                    if rule['rule']['_mac_'] == mac and name == '(null)':
                        continue
                    else:
                        updated_port_acl.insert(i, rule)
                        i = i + 1

            except KeyError:
                updated_port_acl.insert(i, rule)
                i = i + 1

        all_acls['acls'][aclname] = updated_port_acl

        config_parser.write_yaml_file(all_acls, self.config.acl_config_file + '.tmp')

    def add_acls(self, mac, user, rules, dp_name, switchport):
        """Adds the acls to a port acl that the mac address is associated with,
         in the faucet configuration file.
        Args:        
            mac MAC address of authenticated user
            user username of authenticated user
            rules List of ACL rules to be applied to port that mac is associated with.
        """
        self.logger.info("rules")
        self.logger.info(rules)
        # TODO might want to make it so that acls can be added to any port_acl,
        # load acls from faucet.yaml
        if dp_name == '' or switchport == -1:
            self.logger.warn(("Error switchname '{}' or switchport '{}' is unknown. Cannot add acls for authed user '{}' on MAC '{}'".format(
                dp_name, switchport, user, mac)))
            return
        else:
            all_acls = config_parser.load_acls(self.config.acl_config_file) #, dp_name, switchport)
        aclname = 'port_' + dp_name + '_' + str(switchport)

        self.logger.info(all_acls)
        port_acl = all_acls['acls'][aclname]

        i = 0
        # apply ACL for user to the switchport ACL
        new_port_acl = []
        inserted = False
        self.logger.info("portacl")
        self.logger.info((type(port_acl)))
        self.logger.info(port_acl)
        hashable_port_acl = auth_app_utils.get_hashable_list(port_acl)
        for rule in port_acl:

            if '_name_' in rule['rule'] and rule['rule']['_name_'] == '__1x-redirect__':
                new_port_acl.insert(i, rule)
                i = i + 1
            elif '_name_' in rule['rule'] and rule['rule']['_name_'] == '__unauth-redirect__':
                if not inserted:
                    inserted = True
                    for port_to_apply, new_rules in list(rules.items()):
                        for new_rule in new_rules:
                            if not auth_app_utils.is_rule_in(new_rule, hashable_port_acl):
                            # only insert the new rule if it is not already in the port_acl (config file)
                                new_port_acl.insert(i, new_rule)
                                i = i + 1

                new_port_acl.insert(i, rule)
                i = i + 1
            else:
                # insert new rule if not already.
                if not inserted:
                    inserted = True
                    self.logger.info(("\n\nrules:\n{}".format(rules)))
                    for new_rule in rules['port_' + dp_name + '_' + str(switchport)]:
                        self.logger.info(("\n\nnewrule:\n{}".format(new_rule)))
                        if not auth_app_utils.is_rule_in(new_rule, hashable_port_acl):
                            new_port_acl.insert(i, new_rule)
                            i = i + 1
                new_port_acl.insert(i, rule)
                i = i + 1
        if not inserted:
            inserted = True
            for new_rule in rules:
                if not auth_app_utils.is_rule_in(new_rule, hashable_port_acl):
                    new_port_acl.insert(i, new_rule)
                    i = i + 1

        all_acls['acls'][aclname] = new_port_acl
        self.logger.info('writing the following acls')
        self.logger.info(all_acls)
        config_parser.write_yaml_file(all_acls, self.config.acl_config_file + '.tmp')

    def do_POST(self):
        """Serves HTTP POST requests.
        Inherited from BaseHttpRequestHandler.
        """
        json_data = self.check_if_json()
        if json_data is None:
            return

        if self.path == self.config.dot1x_auth_path:
            self.authenticate(json_data)
        else:
            self.send_error('Path not found\n')

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

            switchname, switchport = self._get_dp_name_and_port(mac)
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
            else:
                rules = self.rule_gen.get_rules(user, 'port_' + switchname + '_' + str(switchport)
                                                , mac)
            message = 'authenticated new client({}) at MAC: {}\n'.format(
                user, mac)
            THREAD_LOCK.acquire()
            conf_fd = lockfile.lock(self.config.faucet_config_file, os.O_RDWR)

        self.add_acls(mac, user, rules, switchname, switchport)
        self.swap_temp_file()

        lockfile.unlock(conf_fd)
        THREAD_LOCK.release()
        self.send_signal(signal.SIGHUP)
        self.logger.error(config_parser.load_acls(self.config.acl_config_file))
        #write response
        self._set_headers(200, 'text/html')
        self.wfile.write(message.encode(encoding='utf-8'))
        self.log_message('%s', message)

    def swap_temp_file(self):
        """Removes the old config file and renames the temporary
        one to become the original.
        """
        os.remove(self.config.acl_config_file)
        os.rename(self.config.acl_config_file + '.tmp', self.config.acl_config_file)

    def deauthenticate(self, mac, username):
        """Deauthenticates the mac and username by removing related acl rules
        from Faucet's config file.
        Args:
            mac (str): mac address string to deauth
            username (str): username to deauth.
        """
        self.logger.info('---deauthenticated: {} {}'.format(mac, username))
        switchname, switchport = self._get_dp_name_and_port(mac)

        THREAD_LOCK.acquire()
        conf_fd = lockfile.lock(self.config.faucet_config_file, os.O_RDWR)

        switchname, switchport = self._get_dp_name_and_port(mac)
        if switchname == '' or switchport == -1:
            self.logger.warn(("Error switchname '{}' or switchport '{}' is unknown. Cannot remove acls for deauthed user '{}' on MAC '{}'".format(
                switchname, switchport, username, mac)))
        else:
            self.remove_acls(mac, username, switchname, switchport)
            self.swap_temp_file()
        lockfile.unlock(conf_fd)
        THREAD_LOCK.release()
        # TODO probably shouldn't return success if the switch/port cannot be found.
        # but at this stage auth server (hostapd) can't do anything about it.
        # Perhaps look into the CoA radius thing, so that process looks like:
        #   - client 1x success, send to here.
        #   - can't find switch. return failure.
        #   - hostapd revokes auth, so now client is aware there was an error.
        self._set_headers(200, 'text/html')
        message = 'deauthenticated client {} at {} \n'.format(username, mac)
        self.wfile.write(message.encode(encoding='utf-8'))
        self.log_message('%s', message)
        self.send_signal(signal.SIGHUP)

    def send_signal(self, signal_type):
        ''' Send a signal to the controller to indicate a change in config file
        Args:
            signal_type: SIGUSR1 for dot1xforwarder, SIGUSR2 for CapFlow
        '''
        with open(self.config.contr_pid_file, 'r') as pid_file:
            contr_pid = int(pid_file.read())
            os.kill(contr_pid, signal_type)
            self.logger.info('sending signal {} to pid {}'.format(signal_type, contr_pid))

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
        data = self.rfile.read(content_length).decode('utf-8')
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
    logger = get_logger('httpserver', conf.logger_location, logging.DEBUG, 0)
    HTTPHandler.logger = logger
    HTTPHandler.config = conf
    HTTPHandler.rule_gen = rule_generator.RuleGenerator(conf.rules)
    server = ThreadedHTTPServer(('', conf.listen_port), HTTPHandler)
    logger.info(('starting server %d', conf.listen_port))
    server.serve_forever()

