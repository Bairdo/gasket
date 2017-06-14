# pylint: disable=import-error
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

import argparse
import cgi
import json
import logging
import os
import re
import signal
import threading
import yaml
import requests

import time

from valve_util import get_logger
import config_parser
import my_lockfile as lockfile
from auth_config import AuthConfig
import rule_generator

class Proto():
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

thread_lock = threading.Lock()

class HashableDict(dict):
    '''
        Copied from http://stackoverflow.com/a/1151686
    '''
    def __key(self):
        return tuple((k,self[k]) for k in sorted(self))

    def __hash__(self):
        return hash(self.__key())

    def __eq__(self, other):
        return self.__key() == other.__key()


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
        prom_url = self.config.prom_url
        prom_vars = []
        for prom_line in requests.get(prom_url).text.split('\n'):
            if not prom_line.startswith('#'):
                prom_vars.append(prom_line)
        return '\n'.join(prom_vars)


    def _float_to_mac(self, mac_as_float_str):
        h = '%012x' % int(mac_as_float_str.split('.')[0])
        macstr = h[:2] + ':' + h[2:4] + \
                     ':' + h[4:6] + ':' + h[6:8] + \
                     ':' + h[8:10] + ':' +  h[10:12]
        return macstr


    def _dpid_name_to_map(self, lines):
        '''Converts a list of lines containing the faucet_config_dp_name,
           (from prometheus client (faucet)) to a dictionary.
        :param lines list
        :returns dictionary
        '''
        d = {}
        self.logger.info("dpid name to map")
        for l in lines:
            # TODO maybe dont use regex?
            self.logger.info(l)
            _, _, dpid, _, name, _ = re.split('[{=",]+', l)
            d[dpid] = name
        return d

    def _dp_port_mode_to_map(self, lines):
        '''Converts a list of lines containing dp_port_mode,
           (from prometheus client (faucet)) to a dictionary dictionary.
        :param lines list
        :returns dictionary
        '''
        d = {}
        for l in lines:
            _, _, dpid, _, port, mode_int, _ = re.split('\W+', l)
            if int(mode_int) == 1:
                mode = 'access'
            else:
                mode = None
            if dpid not in d:
                d[dpid] = {}
            
            d[dpid][port] = mode
        self.logger.info(("dp_port_mode_to_map returns: {}".format(d)))
        return d

    def _get_dp_name_and_port(self, mac):
        """
        Queries the prometheus faucet client, and returns the 'access port' that the mac address is connected on.
        :param mac MAC address to find port for.
        :returns dp name & port number.
        """
        # query faucets promethues.
        prom_txt = self.scrape_prometheus()

        prom_mac_table = []
        prom_name_dpid = []
        prom_dpid_port_mode = []
        for l in prom_txt.splitlines():
            self.logger.info(l)
            if l.startswith('learned_macs'):
                prom_mac_table.append(l)
            if l.startswith('faucet_config_dp_name'):
                prom_name_dpid.append(l)
            if l.startswith('dp_port_mode'):
                # TODO this is not implemented on the faucet side yet.
                prom_dpid_port_mode.append(l)

        dpid_name = self._dpid_name_to_map(prom_name_dpid)       
        dp_port_mode = self._dp_port_mode_to_map(prom_dpid_port_mode)
 
        ret_port = -1
        ret_dp_name = ""
        for l in prom_mac_table:
            labels, float_as_mac = l.split(' ')
            self.logger.info(("int as mac{}".format(self._float_to_mac(float_as_mac))))
            if mac == self._float_to_mac(float_as_mac):
                # if this is also an access port, we have found the dpid and the port
                _, _, dpid, _, n, _, port, _, vlan, _ = re.split('\W+', labels)
                if dpid in dp_port_mode and \
                        port in dp_port_mode[dpid] and \
                        dp_port_mode[dpid][port] == 'access':
                    ret_port = int(port)
                    ret_dp_name = dpid_name[dpid]
                    break
        self.logger.info(("name: {} port: {}".format(ret_dp_name, ret_port)))
        return ret_dp_name, ret_port
       
    def remove_acls_startswith(self, mac, name, switchname, switchport):
        self.remove_acls(mac, name, switchname, switchport, startswith=True)

    def remove_acls(self, mac, name, switchname, switchport, startswith=False):
        """
        Removes the ACLS for the mac and name from the config file.
        NOTE: only from the port that the mac address is authenticated on, currently.
        :param mac mac address of authenticated user
        :param name the 'name' field of the acl rule in faucet.yaml, generally username or captiveportal_*
        :param startswith Boolean value should name field be compared using string.startswith(), or == equality
        """ 

        # TODO remove rules from any port acl.
        # load faucet.yaml and its included yamls
        all_acls = config_parser.load_acls(self.config.acl_config_file) #, switchname, switchport)

        aclname = 'port_' + switchname + '_' + str(switchport)
        port_acl = all_acls['acls'][aclname]
        i = 0
        updated_port_acl = []
        for rule in port_acl:
            try:
                if rule['rule']['_mac_'] is not None and rule['rule']['_name_'] is not None:
                    if startswith and rule['rule']['_mac_'] == mac and rule['rule']['_name_'].startswith(name):
                        continue
                    if rule['rule']['_mac_'] == mac and rule['rule']['_name_'] == name:
                        continue
                    if rule['rule']['_mac_'] == mac and '(null)' == name:
                        continue
                    else:
                        updated_port_acl.insert(i, rule)
                        i = i + 1
               
            except KeyError:
                updated_port_acl.insert(i, rule)
                i = i + 1
      
        all_acls['acls'][aclname] = updated_port_acl

        config_parser.write_yaml_file(all_acls, self.config.acl_config_file, self.logger)

    def _is_rule_in(self, rule, list_):
        """Searches a list of HashableDicts for an item equal to rule.
        :param rule an acl dict
        :param list_ a list of HashableDicts
        :return True if rule is is equal to item in list_, false otherwise
        """
        hash_rule = HashableDict(rule)
        for item in list_:
            if hash_rule == item:
                return True
        return False

    def _get_hashable_list(self, list_):
        """Creates a list of HashableDict for a list of dict.
        :param list_ a list of dicts (standard python version)
        :return a list of HashableDict
        """
        hash_list = []

        for item in list_:
            hash_list.append(HashableDict(item))

        return hash_list

    def add_acls(self, mac, user, rules, dp_name, switchport):
        """
        Adds the acls to a port acl that the mac address is associated with, in the faucet configuration file.
        :param mac MAC address of authenticated user
        :param user username of authenticated user
        :param rules List of ACL rules to be applied to port that mac is associated with.
        """
        self.logger.info("rules")
        self.logger.info(rules)
        # TODO might want to make it so that acls can be added to any port_acl,
        # load acls from faucet.yaml
        if dp_name == '' or switchport == -1 :
            self.logger.info(("Error switchname '{}' or switchport '{}' is unknown. Cannot add acls for authed user '{}' on MAC '{}'".format(
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
        hashable_port_acl = self._get_hashable_list(port_acl)
        for rule in port_acl:

            if '_name_' in rule['rule'] and rule['rule']['_name_'] == 'd1x':
                new_port_acl.insert(i, rule)
                i = i + 1
            elif '_name_' in rule['rule'] and rule['rule']['_name_'] == 'redir41x':
                if not inserted:
                    inserted = True
                    for port_to_apply , new_rules in list(rules.items()):
                        for new_rule in new_rules:
                            if not self._is_rule_in(new_rule, hashable_port_acl):
                            # only insert the new rule if it is not already in the port_acl (config file)
                            #if rule is in rules  
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
                        if not self._is_rule_in(new_rule, hashable_port_acl):
                            new_port_acl.insert(i, new_rule)
                            i = i + 1
                new_port_acl.insert(i, rule)
                i = i + 1
        if not inserted:
           inserted = True
           for new_rule in rules:
               if not self._is_rule_in(new_rule, hashable_port_acl):
                   new_port_acl.insert(i, new_rule)
                   i = i + 1

        all_acls['acls'][aclname] = new_port_acl
        # TODO yaml
        self.logger.info('writing the following acls')
        self.logger.info(all_acls)
        config_parser.write_yaml_file(all_acls, self.config.acl_config_file, self.logger)

    def do_POST(self):
        json_data = self.check_if_json()
        if json_data == None:
            return

        if self.path == self.config.dot1x_auth_path: # or self.path == self.config.captive_portal_auth_path:
            self.authenticate(json_data)
#        elif self.path == self.config.idle_path:
#            self.idle(json_data)
        else:
            self.send_error('Path not found\n')

    def do_DELETE(self):
        json_data = self.check_if_json()
        if json_data == None:
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
            if switchname == '' or switchport == -1 :
                self.logger.info(("Error switchname '{}' or switchport '{}' is unknown. Cannot generate acls for deauthed user '{}' on MAC '{}'".format(
                                    switchname, switchport, user, mac)))
                #write response
                message = 'cant auth'
                # auth server doesnt handle errors at this stage so return 200
                self._set_headers(200, 'text/html')
                self.wfile.write(message.encode(encoding='utf-8'))
                self.log_message('%s', message)
                return
            else:
                rules = self.rule_gen.get_rules(user, 'port_' + switchname + '_' + str(switchport), mac)
            message = 'authenticated new client({}) at MAC: {}\n'.format(
                user, mac)
            # TODO lock
            thread_lock.acquire()
            conf_fd = lockfile.lock(self.config.faucet_config_file, os.O_RDWR)

        self.add_acls(mac, user, rules, switchname, switchport)
        # TODO unlock
        lockfile.unlock(conf_fd)
        thread_lock.release()
        os.system('lsof | grep -i "\.yaml"')
        self.send_signal(signal.SIGHUP)

        #write response
        self._set_headers(200, 'text/html')
        self.wfile.write(message.encode(encoding='utf-8'))
        self.log_message('%s', message)

    def idle(self, json_data):
        if not ('mac' in json_data and 'retrans' in json_data):
            self.send_error('Invalid form\n')
            return

        message = 'Idle user on {} has had {} retransmissions'.format(
                    json_data['mac'], json_data['retrans'])
        self._set_headers(200, 'text/html')
        self.log_message('%s', message)
        self.wfile.write(message.encode(encoding='utf-8'))
        if json_data['retrans'] > self.config.retransmission_attempts:
            # TODO lock
            thread_lock.acquire()
            conf_fd = lockfile.lock(self.config.faucet_config_file, os.O_RDWR)

            self._add_cp_acls(json_data['mac'])

            # TODO unlock
            lockfile.unlock(conf_fd)
            thread_lock.release()

            self.send_signal(signal.SIGHUP)
            message = 'Idle user on {} has been made to use captive portal after {} retransmissions\n'.format(
            json_data['mac'], json_data['retrans'])

    def deauthenticate(self, mac, username):
        self.logger.info('---deauthenticated: {} {}'.format(mac, username))
        switchname, switchport = self._get_dp_name_and_port(mac)
        # TODO lock
        thread_lock.acquire()
        conf_fd = lockfile.lock(self.config.faucet_config_file, os.O_RDWR)
       
        switchname, switchport = self._get_dp_name_and_port(mac)
        if switchname == '' or switchport == -1 :
            self.logger.info(("Error switchname '{}' or switchport '{}' is unknown. Cannot remove acls for deauthed user '{}' on MAC '{}'".format(
                                    switchname, switchport, username, mac)))
        else:
            self.remove_acls(mac, username, switchname, switchport)
        # TODO unlock
        lockfile.unlock(conf_fd)
        thread_lock.release()

        self.send_signal(signal.SIGHUP)

        self._set_headers(200, 'text/html')
        message = 'deauthenticated client {} at {} \n'.format(username, mac)
        self.wfile.write(message.encode(encoding='utf-8'))
        self.log_message('%s', message)

    def send_signal(self, signal_type):
        ''' Send a signal to the controller to indicate a change in config file

        :param signal_type: SIGUSR1 for dot1xforwarder, SIGUSR2 for CapFlow
        '''
        with open(self.config.contr_pid_file, 'r') as f:
            contr_pid = int(f.read())
            os.kill(contr_pid, signal_type)
            self.logger.info('sending signal {} to pid {}'.format(signal_type, contr_pid))

    def check_if_json(self):
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
    logger = get_logger(
            'httpserver', conf.logger_location, logging.DEBUG, 0)
    HTTPHandler.logger = logger
    HTTPHandler.config = conf
    HTTPHandler.rule_gen = rule_generator.RuleGenerator(conf.rules)
    server = ThreadedHTTPServer(('', conf.listen_port), HTTPHandler)
    logger.info(('starting server {}'.format(conf.listen_port)))
    server.serve_forever()

