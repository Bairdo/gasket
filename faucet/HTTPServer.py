from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

import argparse
import cgi
import json
import os
import signal
import threading

import time

import ruamel.yaml
from ruamel.yaml.comments import CommentedMap
from ruamel.yaml.util import load_yaml_guess_indent
from ruamel.yaml.scalarstring import DoubleQuotedScalarString

import lockfile
import auth_config_parser as ACP

CAPFLOW = "/v1.1/authenticate/auth"
AUTH_PATH = "/authenticate/auth"
IDLE_PATH = "/idle"

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

class AuthConfig():
    """Structure to hold configuration settings
    """
    def __init__(self, filename):
        data, ind, bsi = load_yaml_guess_indent(open(filename, 'r'))
        self.version = data["version"]

        self.contr_pid_file = data["files"]["controller_pid"]
        self.faucet_config_file = data["files"]["faucet_config"]
 
        self.captive_portal_auth_path = data["urls"]["capflow"]
        self.dot1x_auth_path = data["urls"]["dot1x"]
        self.idle_path = data["urls"]["idle"]

        servers = data["servers"]

        self.gateways = []
        for g in servers["gateways"]:
            self.gateways.append(g)

        self.captive_portals = []
        for cp in servers["captive-portals"]:
            self.captive_portals.append(cp)

        # these servers are not currently used by this app.
        self.dot1x_auth_servers = []
        for d in servers["dot1x-servers"]:
            self.dot1x_auth_servers.append(d)

        self.dns_servers = []
        for d in servers["dns-servers"]:
            self.dns_servers.append(d)

        self.dhcp_servers = []
        for d in servers["dhcp-servers"]:
            self.dhcp_servers.append(d)

        self.wins_servers = []
        for w in servers["wins-servers"]:
            self.wins_servers.append(w)

        self.retransmission_attempts = int(data["captive-portal"]["retransmission-attempts"]) 


class HTTPHandler(BaseHTTPRequestHandler):
    '''
    This class receives HTTP messages from the portal about
    the a change of state of the users.
    This could be either a log on or a log off of a user.
    The information is then passed to the controller by
    modifying configuration files as well as sending a signal to it.
    '''

    _contr_pid = -1  #the process ID of the controller
    dot1x_active_file = os.getenv('DOT1X_ACTIVE_HOSTS',
                                  '/etc/ryu/1x_active_users.txt')
    dot1x_idle_file = os.getenv('DOT1X_IDLE_HOSTS',
                                '/etc/ryu/1x_idle_users.txt')
    capflow_file = os.getenv('CAPFLOW_CONFIG', '/etc/ryu/capflow_config.txt')

    config = None


    def _set_headers(self, code, ctype):
        self.send_response(code)
        self.send_header('Content-type', ctype)
        self.end_headers()

    def _is_access_port(self, dpid, port):
        # load faucet.yaml.
        # check field 'mode' to be access
        conf, ind, bsi = load_yaml_guess_indent(open(self.config.faucet_config_file, 'r'))
        switchname = "" 
        for dp in conf["dps"].items():
            if dp[1]["dp_id"] == dpid:
                switchname = dp[0]
                break

        mode = conf["dps"][switchname]["interfaces"][port]["mode"]

        if mode == "access":
            return True

        return False

    def _get_dpid_and_port(self, mac):
        """
        Reads the mac learning file, and returns the 'access port' that the mac address is connected on.
        """
        dpid = ""
        port = ""
        print("about to lock file")
        fd = lockfile.lock("/home/ubuntu/faucet_mac_learning.txt", os.O_RDWR)

        flag = False
        with open("/home/ubuntu/faucet_mac_learning.txt", "r") as mac_learn:
            for l in mac_learn:
                if l.startswith(mac):
                    print(l)
                    tokens = l.split(",")
                    dpid = tokens[1]
                    port = tokens[2]
                    mode = tokens[3].split("\n")[0]
                    if mode == "access":
                        flag = True
                        break
#                    if self._is_access_port(dpid, port):
#                        flag = True
#                        break
        lockfile.unlock(fd)
        if flag:
            return int(dpid), int(port)
        return 0, ""

    def _get_switch_and_port(self, mac):
        """
        Returns the 'switch name' and the port, which are used in the yaml. and can be used by the access operator.
        """
        switch = ""
        switchport = -1

        conf, ind, bsi = load_yaml_guess_indent(open(self.config.faucet_config_file, 'r'))

        # read mac learning file for dp_id and portname.
        
        dp_id, port = self._get_dpid_and_port(mac)

        for dp in conf["dps"].items():
            print(dp_id)
            print(dp[1]["dp_id"])
            if dp[1]["dp_id"] == dp_id:
                switch = dp[0]
                break
        print(conf["dps"][switch]["interfaces"])
#        print(type(port))
#        switchport = config["dps"][switch]["interfaces"][port][0]


        return switch, port

    def _get_cp_arp_acls(self, mac):
        """Creates two rules for allowing ARP requests from/to MAC.
        Note: the yaml keys 'name' and 'mac' are used to identify the rule to a user,
             so that when they log off, if there is already a rule that is the same, that one will not be removed.
            If we were to just use 'dl_src', there is the potential for the rule to already exist, although possibly unlikley.
        :param mac MAC address of the client
        :return list of rules (ruamel.CommentedMap, which is like a normal dict)
        """

        print(self.config.gateways)
        print(self.config.gateways[0]["gateway"])
        # TODO might need to break this out into dhcp, dns, gateway router, etc... for real world.       
        # TODO support multiple gateways and captive-portals somehow.

        # Allow ARP to gateway to proceed.
        # The point of changing the dst mac is so that other hosts do not learn about the 
        #  unauthenticated host, (and vice versa as no arp replies should be sent,
        #  from anyone but the gateway or captive portal)
        arpReq = CommentedMap()
        arpReq["name"] = "captiveportal_arp"
        arpReq["mac"] = mac
        arpReq["dl_src"] = DoubleQuotedScalarString(mac)
        arpReq["dl_type"] = Proto.ETHER_ARP
        arpReq["arp_tpa"] = self.config.gateways[0]["gateway"]["ip"]
        arpReq["actions"] = CommentedMap()
        arpReq["actions"]["allow"] = 1
        arpReq["actions"]["dl_dst"] = self.config.gateways[0]["gateway"]["mac"]

        areq = CommentedMap()
        areq["rule"] = arpReq

        # redirect the rest of arp to a captive portal.

        # The idea of this was to get the portal to reply to all arp requests,
        #  so that any tcp connections (which need arp to happen first) that are not
        #  destined to/past the gateway will be sent to the portal, which can then reply to the
        #  arp. However this will result in poisoning the clients arp cache, which may
        #  cause more trouble than it is worth.
        # The portal currently does not do anything with these packets.
        arpReply = CommentedMap()
        arpReply["name"] = "captiveportal_arp"
        arpReply["mac"] = mac
        arpReply["dl_src"] = DoubleQuotedScalarString(mac)
        arpReply["dl_type"] = Proto.ETHER_ARP
        arpReply["actions"] = CommentedMap()
        arpReply["actions"]["allow"] = 1
        arpReply["actions"]["dl_dst"] = self.config.captive_portals[0]["captive-portal"]["mac"]

        arep = CommentedMap()
        arep["rule"] = arpReply

        return [areq, arep]

    def _get_cp_dhcp_acls(self, mac):
        # allow dhcp
        dhcpReply = CommentedMap()
        dhcpReply["name"] = "captiveportal_dhcp"
        dhcpReply["mac"] = mac
        dhcpReply["dl_src"] = DoubleQuotedScalarString(mac)
        # TODO should we match on all these fields (dl_dst, ip.src/dst. udp.src)? pretty sure at some point
        #  I saw a DHCP REQUEST with the servers IP address as the destination,
        #  which would mean this rule would not be hit.
#        dhcpReply["dl_dst"] = "ff:ff:ff:ff:ff:ff" # ignore for mean time.
#   could also add ip.src 0.0.0.0 and dst 255.255.255.255 to resp and repl
        dhcpReply["dl_type"] = Proto.ETHER_IPv4
        dhcpReply["ip_proto"] = Proto.IP_UDP
#        dhcpReply["udp_src"] = Proto.DHCP_CLIENT
        dhcpReply["udp_dst"] = Proto.DHCP_SERVER_PORT
        dhcpReply["actions"] = CommentedMap()
        dhcpReply["actions"]["allow"] = 1
        # TODO could possibly rewrite MAC to DHCP server. and maybe IP

        dhrep = CommentedMap()
        dhrep["rule"] = dhcpReply

        return [dhrep]

    def _get_cp_dns_acls(self, mac):
        # TODO currently allows dns to any server, as long as it uses the DNS port.
        #  Change so either DNS only allowed to ones specified in config, 
        #  OR redirect to ones in config.
        #  - Either way allow multiple DNS servers to be used.

        # allow dns
        dnsReply = CommentedMap()
        dnsReply["name"] = "captiveportal_dns"
        dnsReply["mac"] = mac
        dnsReply["dl_src"] = DoubleQuotedScalarString(mac)
        dnsReply["dl_type"] = Proto.ETHER_IPv4
        dnsReply["ip_proto"] = Proto.IP_UDP
        dnsReply["udp_dst"] = Proto.DNS_PORT
        dnsReply["actions"] = CommentedMap()
        dnsReply["actions"]["allow"] = 1

        dnsrep = CommentedMap()
        dnsrep["rule"] = dnsReply

        return [dnsrep]

    def _get_cp_tcp_acls(self, mac):
        """
        :param mac client's MAC address
        :return List of Rules to redirect mac to a NFV portal by changing the dst MAC to the portal.
        """
        # TODO could possibly do a form of load balancing here,
        #  by selecting a different portal dst mac address.
        tcpFwd = CommentedMap()
        tcpFwd["name"] = "captiveportal_tcp"
        tcpFwd["mac"] = mac
        tcpFwd["dl_src"] = DoubleQuotedScalarString(mac)
        tcpFwd["dl_type"] = Proto.ETHER_IPv4
        tcpFwd["ip_proto"] = Proto.IP_TCP
        tcpFwd["tcp_dst"] = Proto.HTTP_PORT
        tcpFwd["actions"] = CommentedMap()
        tcpFwd["actions"]["allow"] = 1
        tcpFwd["actions"]["dl_dst"] = self.config.captive_portals[0]["captive-portal"]["mac"]

        ret = CommentedMap()
        ret["rule"] = tcpFwd 

        return [ret]

    def _get_captive_portal_acls(self, mac):
        """Generates the rules for mac to be able to use the captive portal.
        :param mac MAC address of client
        :return List of rules to be applied to a port ACL for the specified MAC address.
        """
        rules = []
        rules.extend(self._get_cp_arp_acls(mac))
        rules.extend(self._get_cp_dhcp_acls(mac))
        rules.extend(self._get_cp_dns_acls(mac))
        rules.extend(self._get_cp_tcp_acls(mac))

        return rules

    def _add_cp_acls(self, mac):
        """
        Adds the acls for captive portal redirection, to the port that mac is associated with.
        """
        rules = self._get_captive_portal_acls(mac)
        self.add_acls(mac, None, rules)



       
    def remove_acls_startswith(self, mac, name):
        self.remove_acls(mac, name, startswith=True)

    def remove_acls(self, mac, name, startswith=False):
        """
        Removes the ACLS for the mac and name from the config file.
        :param mac mac address of authenticated user
        :param name the 'name' field of the acl rule in faucet.yaml, generally username or captiveportal_*
        """ 
         # get switchport
        switchname, switchport = self._get_switch_and_port(mac)
	    # load faucet.yaml and its included yamls
        acl, dp, vlan = ACP.load_config_file(self.config.faucet_config_file)


        #aclname = config["dps"][switchname]["interfaces"][switchport]["acl_in"]
        for port_acl in acl[0].items():
            aclname = port_acl[0]
            i = 0
            updated_port_acl = []
            for rule in port_acl[1]:
                print(rule)
                try:
                    if rule["rule"]["mac"] is not None and rule["rule"]["name"] is not None:
                        if startswith and rule["rule"]["mac"] == mac and rule["rule"]["name"].startswith(name):
                            print("deleted - startswith=true")
                            continue
                        if rule["rule"]["mac"] == mac and rule["rule"]["name"] == name:
                            print("deleted - startswith=false")
                            continue
                        else:
                            updated_port_acl.insert(i, rule)
                            i = i + 1
                   
                except KeyError:
                    updated_port_acl.insert(i, rule)
                    i = i + 1
            acl[0][aclname] = updated_port_acl

        ACP.write_config_file("acls", acl)


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

    def add_acls(self, mac, user, rules):
        """
        Adds the acls to a port acl that the mac address is associated with, in the faucet configuration file.
        :param mac MAC address of authenticated user
        :param user username of authenticated user
        :param rules List of ACL rules to be applied to port that mac is associated with.
        """
        # get switchport
        switchname, switchport = self._get_switch_and_port(mac) 
        # load faucet.yaml
        acl, dp, vlan = ACP.load_config_file(self.config.faucet_config_file)
        
        print("adding acls")
        print("switchname {0}, port {1}".format(switchname, switchport))
        aclname = dp[0][switchname]["interfaces"][switchport]["acl_in"]

        port_acl = acl[0][str(aclname)]
        i = 0
        # apply ACL for user to the switchport ACL
        new_port_acl = []
        inserted = False
        #new_rules = set(rules).difference(port_acl)

        hashable_port_acl = self._get_hashable_list(port_acl)
        for rule in port_acl:
#            print(rule)
            #rule = rule["rule"]
            if "name" in rule["rule"] and rule["rule"]["name"] == "d1x":
#                print("d1x: " + str(rule))
                new_port_acl.insert(i, rule)
                i = i + 1
            elif "name" in rule["rule"] and rule["rule"]["name"] == "redir41x":
                if not inserted:
                    inserted = True
                    for new_rule in rules:
                        if not self._is_rule_in(new_rule, hashable_port_acl):
                            # only insert the new rule if it is not already in the port_acl (config file)
                            #if rule is in rules
#                            print("new rule: " + str(new_rule))
                            new_port_acl.insert(i, new_rule)
                            i = i + 1
#                print("redir41x: " + str(rule))
                new_port_acl.insert(i, rule)
                i = i + 1
            else:
                # insert new rule if not already.
                if not inserted:
                    print("inserting rule")
                    inserted = True
                    for new_rule in rules:
                        print("insert loop")
                        if not self._is_rule_in(new_rule, hashable_port_acl):
#                            print("new rule: " + str(rule))
                            new_port_acl.insert(i, new_rule)
                            i = i + 1
#                print("un reck: " + str(rule))
                new_port_acl.insert(i, rule)
                i = i + 1
#        print("npa" + str(new_port_acl))
        acl[0][aclname] = new_port_acl

        ACP.write_config_file("acls", acl)

    def do_POST(self):
        print("do_post config") 
        json_data = self.check_if_json()
        if json_data == None:
            return

        if self.path == AUTH_PATH or self.path == CAPFLOW:
            self.authenticate(json_data)
        elif self.path == IDLE_PATH:
            self.idle(json_data)
        else:
            self.send_error('Path not found\n')

    def do_DELETE(self):
        json_data = self.check_if_json()
        if json_data == None:
            return

        if self.path == AUTH_PATH:
            #check json has the right information
            if not ("mac" in json_data and "user" in json_data):
                self.send_error('Invalid form\n')
                return
            self.deauthenticate(json_data["mac"], json_data["user"])
        elif self.path == CAPFLOW:
            #check json has the right information
            if not ("mac" in json_data and "user" in json_data):
                self.send_error('Invalid form\n')
                return
            print("deauth capflow")
            self.deauthenticate(json_data["mac"], json_data["user"])
        else:
            self.send_error('Path not found\n')

    def get_users_rules(self, mac, user):
        """
        gets the ACL rules for an authenticated user.
        TODO: in future make this get the rules from somewhere else, might also want to provide
            other parameters (e.g. groups) for generating the ACL.
        :param mac mac address of authenticated user
        :param user username of the authenticated user
            encode the user in the rule (somehow) for easy removal.
        """
        nr1 = CommentedMap()
        nr1["name"] = user
        nr1["mac"] = mac
        nr1["dl_src"] = DoubleQuotedScalarString(mac)
        nr1["dl_type"] = 0x800
        nr1["nw_dst"] = DoubleQuotedScalarString('8.8.8.8')
        nr1["actions"] = CommentedMap()
        nr1["actions"]["allow"] = 0
        nrd1 = CommentedMap()
        nrd1["rule"] = nr1

        nr = CommentedMap()
        nr["name"] = user
        nr["mac"] = mac
        nr["dl_type"] = 0x800
        nr["dl_src"] = DoubleQuotedScalarString(mac)
        nr["actions"] = CommentedMap()
        nr["actions"]["allow"] = 1
        nrd = CommentedMap()
        nrd["rule"] = nr

        arp = CommentedMap()
        arp["name"] = user
        arp["mac"] = mac
        arp["dl_src"] = DoubleQuotedScalarString(mac)
        arp["dl_type"] = 0x0806
        arp["actions"] = CommentedMap()
        arp["actions"]["allow"] = 1
        arpd = CommentedMap()
        arpd["rule"] = arp
        

        rules = [nrd1, nrd, arpd]
        return rules
       

    def authenticate(self, json_data):
        conf_fd = None
        if self.path == AUTH_PATH:  #request is for dot1xforwarder
            if not ("mac" in json_data and "user" in json_data):
                self.send_error('Invalid form\n')
                return

            #valid request format so new user has authenticated
#            self.write_to_file(self.dot1x_active_file, json_data["mac"],
#                              json_data["user"])
            mac = json_data["mac"]
            user = json_data["user"]
            rules = self.get_users_rules(mac, user)
            message = "authenticated new client({}) at MAC: {}\n".format(
                user, mac)
            # TODO lock
            thread_lock.acquire()
            print("auth locking faucet config")
            conf_fd = lockfile.lock(self.config.faucet_config_file, os.O_RDWR)
            print("auth locked faucet config")
        else:  #request is for CapFlow
            if not ("ip" in json_data and "user" in json_data and "mac" in json_data):
                self.send_error('Invalid form\n')
                return

            #valid request format so new user has authenticated

            mac = json_data["mac"]
            user = json_data["user"]
            ip = json_data["ip"]

            rules = self.get_users_rules(mac, user)
            message = "authenticated new client({}) at MAC: {} and ip: {}\n".format(
                user, mac, ip)
            # remove the redirect to captive portal acl rules for the mac that just authed.
            # TODO does removal happen to early, and that we loose the end of one of the TCP connections to the cp?
            # TODO lock
            thread_lock.acquire()
            print("auth-cp locking faucet config")
            conf_fd = lockfile.lock(self.config.faucet_config_file, os.O_RDWR)
            print("auth-cp locked faucet config")
            self.remove_acls_startswith(mac, "captiveportal_")

#        time.sleep(300)
        self.add_acls(mac, user, rules)
        # TODO unlock
        lockfile.unlock(conf_fd)
        print("auth unlocked faucet config")
        thread_lock.release()

        self.send_signal(signal.SIGHUP)

        #write response
        self._set_headers(200, 'text/html')
        self.wfile.write(message.encode(encoding="utf-8"))
        self.log_message("%s", message)

    def idle(self, json_data):
        if not ("mac" in json_data and "retrans" in json_data):
            self.send_error("Invalid form\n")
            return

        self.write_to_file(self.dot1x_idle_file, json_data["mac"],
                           json_data["retrans"])
#        self.send_signal(signal.SIGUSR1) retransmission_attempts
        message = "Idle user on {} has had {} retransmissions".format(
                    json_data["mac"], json_data["retrans"])
        self._set_headers(200, 'text/html')
        self.log_message("%s", message)
        self.wfile.write(message.encode(encoding='utf-8'))
        if json_data["retrans"] > self.config.retransmission_attempts:
            # TODO lock
            thread_lock.acquire()
            print("idle - locking faucet config ")
            conf_fd = lockfile.lock(self.config.faucet_config_file, os.O_RDWR)
            print("idle - locked faucet config")
            self._add_cp_acls(json_data["mac"])
#            time.sleep(300)
            # TODO unlock
            lockfile.unlock(conf_fd)
            thread_lock.release()

            print("idle - unlocking faucet config")
            self.send_signal(signal.SIGHUP)
            message = "Idle user on {} has been made to use captive portal after {} retransmissions\n".format(
            json_data["mac"], json_data["retrans"])



    def deauthenticate(self, mac, username):
        # TODO lock
        thread_lock.acquire()
        print("deauth locking faucet config")
        conf_fd = lockfile.lock(self.config.faucet_config_file, os.O_RDWR)
        print("deauth locked faucet config")
        self.remove_acls(mac, username)
        # TODO unlock
        lockfile.unlock(conf_fd)
        thread_lock.release()
        print("deauth unlocked faucet config")
        self.send_signal(signal.SIGHUP)

        self._set_headers(200, 'text/html')
        message = "deauthenticated client {} at {} \n".format(username, mac)
        self.wfile.write(message.encode(encoding='utf-8'))
        self.log_message("%s", message)

    def write_to_file(self, filename, str1, str2):
        ''' Write two strings which are comma separated, to a file

        :param filename: the name of the file we are writing to
        :param str1: the first string
        :param str2: the second string
        '''
        #try to obtain lock to prevent concurrent access
        fd = lockfile.lock(filename, os.O_APPEND | os.O_WRONLY)
        string = str(str1) + "," + str(str2) + "\n"
        os.write(fd, bytearray(string, 'utf-8'))
        lockfile.unlock(fd)

    def read_file(self, filename, unique_identifier):
        ''' Read a file and delete entries which contain the unique identifier

        :param filename: the name of the file
        :param unique_identifier: the entry which will be deleted
        :return: A tuple which contains a boolean of whether or not the unique 
        identifier was found, and the contents of the file without the unique
        identifier
        '''
        to_write = ""
        file_changed = False
        with open(filename) as file_:
            for line in file_:
                unique_identifier1, user1 = line.split(",")
                if unique_identifier != unique_identifier1:
                    to_write += line
                else:
                    file_changed = True

        return file_changed, to_write

    def send_signal(self, signal_type):
        ''' Send a signal to the controller to indicate a change in config file

        :param signal_type: SIGUSR1 for dot1xforwarder, SIGUSR2 for CapFlow
        '''
        with open(self.config.contr_pid_file, "r") as f:
            self._contr_pid = int(f.read())
        os.kill(self._contr_pid, signal_type)

    def check_if_json(self):
        try:
            ctype, pdict = cgi.parse_header(
                self.headers.get('content-type'))
        except:
            self.send_error("No content-type header\n")
            return None

        if ctype != 'application/json':
            self.send_error("Data is not a JSON object\n")
            return None
        content_length = int(self.headers.get('content-length'))
        data = self.rfile.read(content_length).decode("utf-8")
        try:
            json_data = json.loads(data)
        except ValueError:
            self.send_error("Not JSON object\n")
            return None

        return json_data

    def send_error(self, error):
        self._set_headers(404, 'text/html')
        self.log_message("Error: %s", error)
        self.wfile.write(error.encode(encoding='utf_8'))

    do_GET = do_POST


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", help="location of yaml configuration file")

    args = parser.parse_args()
    config_filename = args.config
    conf = AuthConfig(config_filename)
    
    HTTPHandler.config = conf

    server = ThreadedHTTPServer(('', 8080), HTTPHandler)
    print("starting server")
    server.serve_forever()
