from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

import cgi
import json
import os
import signal

import ruamel.yaml
from ruamel.yaml.comments import CommentedMap
from ruamel.yaml.util import load_yaml_guess_indent
from ruamel.yaml.scalarstring import DoubleQuotedScalarString

import lockfile
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

    _contr_pid = -1  #the process ID of the controller
    dot1x_active_file = os.getenv('DOT1X_ACTIVE_HOSTS',
                                  '/etc/ryu/1x_active_users.txt')
    dot1x_idle_file = os.getenv('DOT1X_IDLE_HOSTS',
                                '/etc/ryu/1x_idle_users.txt')
    capflow_file = os.getenv('CAPFLOW_CONFIG', '/etc/ryu/capflow_config.txt')
    controller_pid_file = os.getenv('CONTR_PID', '/etc/ryu/contr_pid')

    faucet_config_file = os.getenv('FAUCET_CONFIG', '/home/ubuntu/faucet-dev/faucet.yaml') #'/etc/ryu/faucet/faucet.yaml')

    gateway_ip = "10.0.5.2"
    gateway_mac = "52:54:00:12:35:02"
    portal_mac = "08:00:27:00:03:02"
    retransmission_attempts = 3
    
    def _set_headers(self, code, ctype):
        self.send_response(code)
        self.send_header('Content-type', ctype)
        self.end_headers()

    def _is_access_port(self, dpid, port):
        # load faucet.yaml.
        # check field 'mode' to be access
        config, ind, bsi = load_yaml_guess_indent(open(self.faucet_config_file, 'r'))
        switchname = "" 
        for dp in config["dps"].items():
            if dp[1]["dp_id"] == dpid:
                switchname = dp[0]
                break

        mode = config["dps"][switchname]["interfaces"][port]["mode"]

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

        config, ind, bsi = load_yaml_guess_indent(open(self.faucet_config_file, 'r'))

        # read mac learning file for dp_id and portname.
        
        dp_id, port = self._get_dpid_and_port(mac)

        for dp in config["dps"].items():
            print(dp_id)
            print(dp[1]["dp_id"])
            if dp[1]["dp_id"] == dp_id:
                switch = dp[0]
                break
        print(config["dps"][switch]["interfaces"])
        print(type(port))
#        switchport = config["dps"][switch]["interfaces"][port][0]


        return switch, port

    def _get_cp_arp_acls(self, mac):
        """Creates two rules for allowing ARP requests from/to MAC
        :param mac MAC address of the client
        """
        # allow arp
        arpReq = CommentedMap()
        arpReq["name"] = "captiveportal_arp"
        arpReq["mac"] = mac
        arpReq["dl_src"] = DoubleQuotedScalarString(mac)
        arpReq["dl_type"] = Proto.ETHER_ARP
        arpReq["arp_tpa"] = self.gateway_ip
        arpReq["actions"] = CommentedMap()
        arpReq["actions"]["allow"] = 1
        arpReq["actions"]["dl_dst"] = self.gateway_mac

        areq = CommentedMap()
        areq["rule"] = arpReq


        arpReply = CommentedMap()
        arpReply["name"] = "captiveportal_arp"
        arpReply["mac"] = mac
        arpReply["dl_src"] = DoubleQuotedScalarString(mac)
        arpReply["dl_type"] = Proto.ETHER_ARP
        arpReply["actions"] = CommentedMap()
        arpReply["actions"]["allow"] = 1
        arpReply["actions"]["dl_dst"] = self.portal_mac

        arep = CommentedMap()
        arep["rule"] = arpReply

        return [areq, arep]

    def _get_cp_dhcp_acls(self, mac):
        # allow dhcp
        dhcpReply = CommentedMap()
        dhcpReply["name"] = "captiveportal_dhcp"
        dhcpReply["mac"] = mac
        dhcpReply["dl_src"] = DoubleQuotedScalarString(mac)
#        dhcpReply["dl_dst"] = "ff:ff:ff:ff:ff:ff" # ignore for mean time.
#   could also add ip.src 0.0.0.0 and dst 255.255.255.255 to resp and repl
        dhcpReply["dl_type"] = Proto.ETHER_IPv4
        dhcpReply["ip_proto"] = Proto.IP_UDP
#        dhcpReply["udp_src"] = Proto.DHCP_CLIENT
        dhcpReply["udp_dst"] = Proto.DHCP_SERVER_PORT
        dhcpReply["actions"] = CommentedMap()
        dhcpReply["actions"]["allow"] = 1
        # TODO could possibly rewrite MAC to DHCP server.

        dhrep = CommentedMap()
        dhrep["rule"] = dhcpReply

        return [dhrep]

    def _get_cp_dns_acls(self, mac):
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
        :return Rule to redirect mac to a NFV portal by changing the dst MAC to the portal.
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
        tcpFwd["actions"]["dl_dst"] = self.portal_mac

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
        

    def remove_acls(self, mac, user):
        """
        Removes the ACLS for the mac and/or user from the config file.
        :param mac mac address of authenticated user
        :param user username of authenticated user
        """
         # get switchport
        switchname, switchport = self._get_switch_and_port(mac)
	    # load faucet.yaml
        config, ind, bsi = load_yaml_guess_indent(open(self.faucet_config_file, 'r'))


        #aclname = config["dps"][switchname]["interfaces"][switchport]["acl_in"]
        for port_acl in config["acls"].items():
            aclname = port_acl[0]
            i = 0
            updated_port_acl = []
            for rule in port_acl[1]:
                print(rule)
                try:
                    if rule["rule"]["mac"] is not None:
                        if rule["rule"]["mac"] == mac:
                            print("deleted")
                            continue
                        else:
                            updated_port_acl.insert(i, rule)
                            i = i + 1
                   
                except KeyError:
                    updated_port_acl.insert(i, rule)
                    i = i + 1
            config["acls"][aclname] = updated_port_acl
        ruamel.yaml.round_trip_dump(config, open(self.faucet_config_file, 'w'), indent=4, block_seq_indent=4)

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
        # TODO what if the the config is split up accross multiple files?
        config, ind, bsi = load_yaml_guess_indent(open(self.faucet_config_file, 'r'))
        print("adding acls")
        print("switchname {0}, port {1}".format(switchname, switchport))
        aclname = config["dps"][switchname]["interfaces"][switchport]["acl_in"]

        port_acl = config["acls"][str(aclname)]
        i = 0
        # apply ACL for user to the switchport ACL
        new_port_acl = []
        inserted = False
        #new_rules = set(rules).difference(port_acl)

        hashable_port_acl = self._get_hashable_list(port_acl)
        for rule in port_acl:
            print(rule)
            #rule = rule["rule"]
            if "name" in rule["rule"] and rule["rule"]["name"] == "d1x":
                print("d1x: " + str(rule))
                new_port_acl.insert(i, rule)
                i = i + 1
            elif "name" in rule["rule"] and rule["rule"]["name"] == "redir41x":
                if not inserted:
                    inserted = True
                    for new_rule in rules:
                        if not self._is_rule_in(new_rule, hashable_port_acl):
                            # only insert the new rule if it is not already in the port_acl (config file)
                            #if rule is in rules
                            print("new rule: " + str(new_rule))
                            new_port_acl.insert(i, new_rule)
                            i = i + 1
                print("redir41x: " + str(rule))
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
                            print("new rule: " + str(rule))
                            new_port_acl.insert(i, new_rule)
                            i = i + 1
                print("un reck: " + str(rule))
                new_port_acl.insert(i, rule)
                i = i + 1
        print("npa" + str(new_port_acl))
        config["acls"][aclname] = new_port_acl
        ruamel.yaml.round_trip_dump(config, open(self.faucet_config_file, 'w'), indent=4, block_seq_indent=4)


    def do_POST(self):
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
            self.deauthenticate(self.dot1x_active_file, json_data["mac"],
                                signal.SIGUSR1)
        elif self.path == CAPFLOW:
            #check json has the right information
            if "ip" not in json_data:
                self.send_error('Invalid form\n')
                return
            print("deauth capflow")
            self.deauthenticate(self.capflow_file, json_data["mac"],
                                signal.SIGUSR2)
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
        nr["actions"] = OrederedDict()
        nr["actions"]["allow"] = 1
        nrd = CommentedMap()
        nrd["rule"] = nr

        rules = [nrd1, nrd]
        return rules
       

    def authenticate(self, json_data):
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

        else:  #request is for CapFlow
            if not ("ip" in json_data and "user" in json_data and "mac" in json_data):
                self.send_error('Invalid form\n')
                return

            #valid request format so new user has authenticated
#            self.write_to_file(self.capflow_file, json_data["ip"],
#                               json_data["user"])

            mac = json_data["mac"]
            user = json_data["user"]
            ip = json_data["ip"]
            rules = self.get_users_rules(mac, user)
            message = "authenticated new client({}) at MAC: {} and ip: {}\n".format(
                user, mac, ip)

        self.add_acls(mac, user, rules)
        self.send_signal(signal.SIGHUP)

        #write response
        self._set_headers(200, 'text/html')
        self.wfile.write(message)
        self.log_message("%s", message)

    def idle(self, json_data):
        if not ("mac" in json_data and "retrans" in json_data):
            self.send_error("Invalid form\n")
            return

        self.write_to_file(self.dot1x_idle_file, json_data["mac"],
                           json_data["retrans"])
#        self.send_signal(signal.SIGUSR1) retransmission_attempts
        if json_data["retrans"] > self.retransmission_attempts:
            self._add_cp_acls(json_data["mac"])
            self.send_signal(signal.SIGHUP)

        self._set_headers(200, 'text/html')
        message = "Idle user on {} has been made to use captive portal after {} retransmissions\n".format(
            json_data["mac"], json_data["retrans"])
        self.log_message("%s", message)
        self.wfile.write(message.encode(encoding='utf-8'))

    def deauthenticate(self, filename, unique_identifier, signal_type):
        fd = lockfile.lock(filename, os.O_APPEND | os.O_WRONLY)
        changed, to_write = self.read_file(filename, unique_identifier)

        if changed:  #user has been deleted, update the file
            os.ftruncate(fd, 0)  #clear the file
            os.write(fd, to_write)
        lockfile.unlock(fd)
       
        self.remove_acls(unique_identifier, None)
        self.send_signal(signal.SIGHUP)
        self._set_headers(200, 'text/html')
        message = "deauthenticated client at {} \n".format(unique_identifier)
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
        with open(self.controller_pid_file, "r") as f:
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
    server = ThreadedHTTPServer(('', 8080), HTTPHandler)
    print("starting server")
    server.serve_forever()
