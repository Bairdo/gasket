from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from SocketServer import ThreadingMixIn

import os
import signal
import lockfile
import json
import cgi

import ruamel.yaml
from ruamel.yaml.comments import CommentedMap
from ruamel.yaml.util import load_yaml_guess_indent
from ruamel.yaml.scalarstring import DoubleQuotedScalarString

CAPFLOW = "/v1.1/authenticate/auth"
AUTH_PATH = "/authenticate/auth"
IDLE_PATH = "/idle"


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

    def _set_headers(self, code, ctype):
        self.send_response(code)
        self.send_header('Content-type', ctype)
        self.end_headers()

    def _is_access_port(self, dpid, port):
        # load faucet.yaml.
        # check field 'mode' to be access
        config, ind, bsi = load_yaml_guess_indent(open(self.faucet_config_file, 'r'))
        switchname = "" 
        for dp in config["dps"].iteritems():
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
        print "about to lock file"
        fd = lockfile.lock("/home/ubuntu/faucet_mac_learning.txt", os.O_RDWR)

        flag = False
        with open("/home/ubuntu/faucet_mac_learning.txt", "r") as mac_learn:
            for l in mac_learn:
                if l.startswith(mac):
                    print l
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

        for dp in config["dps"].iteritems():
            print dp_id
            print dp[1]["dp_id"]
            if dp[1]["dp_id"] == dp_id:
                switch = dp[0]
                break
        print config["dps"][switch]["interfaces"]
        print type(port)
#        switchport = config["dps"][switch]["interfaces"][port][0]


        return switch, port

    def _get_captive_portal_acls(self, mac):

        # allow arp
        arpReq = dict()
        arpReq["name"] = "captiveportal"
        arpReq["mac"] = mac
        arpReq["dl_src"] = DoubleQuotedScalarString(mac)
        arpReq["dl_type"] = Proto.ETHER_ARP
        arpReq["actions"] = dict()
        arpReq["actions"]["allow"] = 1
        areq = dict()
        areq["rule"] = arpReq


        arpReply = dict()
        arpReply["name"] = "captiveportal"
        arpReply["mac"] = mac
        arpReply["dl_dst"] = DoubleQuotedScalarString(mac)
        arpReply["dl_type"] = Proto.ETHER_ARP
        arpReply["actions"] = dict()
        arpReply["actions"]["allow"] = 1
        arep = dict()
        arep["rule"] = arpReply

        # allow dhcp
        dhcpResp = dict()
        dhcpResp["name"] = "captiveportal"
        dhcpResp["mac"] = mac
        dhcpResp["dl_dst"] = DoubleQuotedScalarString(mac)
        dhcpResp["dl_type"] = Proto.ETHER_IP
        dhcpResp["ip_proto"] = Proto.IP_UDP
        dhcpResp["udp_src"] = Proto.DHCP_SERVER
        dhcpResp["udp_dst"] = Proto.DHCP_CLIENT
        dhcpResp["actions"] = dict()
        dhcpResp["actions"]["allow"] = 1
        dhres = dict()
        dhres["rule"] = dhcpResp

        dhcpReply = dict()
        dhcpReply["name"] = "captiveportal"
        dhcpReply["mac"] = mac
        dhcpReply["dl_src"] = DoubleQuotedScalarString(mac)
#        dhcpReply["dl_dst"] = "ff:ff:ff:ff:ff:ff" # ignore for mean time.
#   could also add ip.src 0.0.0.0 and dst 255.255.255.255 to resp and repl
        dhcpReply["dl_type"] = Proto.ETHER_IP
        dhcpReply["ip_proto"] = Proto.IP_UDP
        dhcpReply["udp_src"] = Proto.DHCP_CLIENT
        dhcpReply["udp_dst"] = Proto.DHCP_SERVER
        dhcpReply["actions"] = dict()
        dhcpReply["actions"]["allow"] = 1
        dhrep = dict()
        dhrep["rule"] = dhcpReply

        # allow dns
        dnsResp = dict()
        dnsResp["name"] = "captiveportal"
        dnsResp["mac"] = mac
        dnsResp["dl_dst"] = DoubleQuotedScalarString(mac)
        dnsResp["dl_type"] = Proto.ETHER_IP
        dnsResp["ip_proto"] = Proto.IP_UDP
        dnsResp["udp_src"] = Proto.UDP_DNS
#        dnsResp["udp_dst"] = #ignoring this for now
        dnsResp["actions"] = dict()
        dnsResp["actions"]["allow"] = 1
        dnsres = dict()
        dnsres["rule"] = dnsResp

        dnsReply = dict()
        dnsReply["name"] = "captiveportal"
        dnsReply["mac"] = mac
        dnsReply["dl_src"] = DoubleQuotedScalarString(mac)
        dnsReply["dl_type"] = Proto.ETHER_IP
        dnsReply["ip_proto"] = Proto.IP_UDP
        dnsReply["udp_dst"] = Proto.UDP_DNS
#        dnsResp["udp_src"] = #ignoring this for now
        dnsReply["actions"] = dict()
        dnsReply["actions"]["allow"] = 1
        dnsrep = dict()
        dnsrep["rule"] = dnsReply
        
        # HTTP NAT
        # match regardless of destination
        # only worry about if its from a mac.
        natFwd = dict()
        natFwd["name"] = "captiveportal"
        natFwd["mac"] = mac
        natFwd["dl_src"] = DoubleQuotedScalarString(mac)
        natFwd["dl_type"] = Proto.ETHER_IP
        natFwd["ip_proto"] = Proto.IP_TCP
#        natFwd["ipv4_src"] = 
        natFwd["tcp_dst"] = Proto.TCP_HTTP
#        natFwd["tcp_src"] = 
        natFwd["actions"] = dict()
        natFwd["actions"]["allow"] = 1
        natFwd["actions"]["ipv4_dst"] = DoubleQuotedScalarString(PORTAL_WS_IP)
        natFwd["actions"]["dl_dst"] = DoubleQuotedScalarString(PORTAL_WS_MAC)
        natFwd["actions"]["output"] = dict()
        natFwd["actions"]["output"]["controller"] = 1 # todo get faucet to support sending packets up to controller

        natf = dict()
        natf["rule"] = natFwd

        rules = [areq, arep, dhres, dhrep, dnsres, dnsrep, natFwd]

        return rules

    def _get_cp_portal_nat_acl(self, client_mac, client_ip, foriegn_mac, foriegn_ip, tcp_dst):
        """
        returns the ACL to be applied on the port_acl for the portal, to perform the reverse NAT operation.
        There will be one of these rules inserted for every tcp connection.
        :param client_mac the MAC address of the host being redirected to the portal.
        :param client_ip the IP address of the host.
        :param foriegn_mac the MAC address of the next hop (probably a router) that the client is trying to access.
        :param foriegn_ip the IP address that the client is trying to access.
        :param tcp_dst the destination tcp port the client is connecting from. tcp_src (assumed to be 80). the names may seem backwards.
        """
        natRev = dict()
        natRev["name"] = "captiveportal"
        natRev["mac"] = client_mac
        natRev["dl_src"] = DoubleQuotedScalarString(PORTAL_WS_MAC)
        natRev["dl_dst"] = DoubleQuotedScalarString(client_mac)
        natRev["dl_type"] = Proto.ETHER_IP
        natRev["ip_proto"] = Proto.IP_TCP
        natRev["ipv4_src"] = DoubleQuotedScalarString(PORTAL_WS_IP)
        natRev["ipv4_dst"] = DoubleQuotedScalarString(client_ip)
        natRev["tcp_src"] = Proto.TCP_HTTP
        natRev["tcp_dst"] = tcp_dst
        natRev["actions"] = dict()
        natRev["actions"]["allow"] = 1
        natRev["actions"]["ipv4_src"] = DoubleQuotedScalarString(foriegn_ip)
        natRev["actions"]["dl_src"] = DoubleQuotedScalarString(foriegn_mac)

        return [natRev]

    def _add_cp_portal_nat_acl(self, cli):
        pass
    
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
        for port_acl in config["acls"].iteritems():
            aclname = port_acl[0]
            i = 0
            updated_port_acl = []
            for rule in port_acl[1]:
                print rule
                try:
                    if rule["rule"]["mac"] is not None:
                        if rule["rule"]["mac"] == mac:
                            print "deleted"
                            continue
                        else:
                            updated_port_acl.insert(i, rule)
                            i = i + 1
                   
                except KeyError:
                    updated_port_acl.insert(i, rule)
                    i = i + 1
            config["acls"][aclname] = updated_port_acl
        ruamel.yaml.round_trip_dump(config, open(self.faucet_config_file, 'w'), indent=4, block_seq_indent=4)

    def add_acls(self, mac, user, rules):
        """
        Adds the acls to a port acl that the mac address is associated with, in the faucet configuration file.
        :param mac mac address of authenticated user
        :param user username of authenticated user
        :param rules List of ACL rules to be applied to port that mac is associated with.
        """
        # get switchport
        switchname, switchport = self._get_switch_and_port(mac)
	    # load faucet.yaml
        config, ind, bsi = load_yaml_guess_indent(open(self.faucet_config_file, 'r'))                
        print "switchname {0}, port {1}".format(switchname, switchport)
        aclname = config["dps"][switchname]["interfaces"][switchport]["acl_in"]

        port_acl = config["acls"][str(aclname)]
        i = 0
        # apply ACL for user to the switchport ACL
        new_port_acl = []
        inserted = False
        for rule in port_acl:
            print rule
            #rule = rule["rule"]
            if "name" in rule["rule"] and rule["rule"]["name"] == "d1x":
                print "d1x: " + str(rule)
                new_port_acl.insert(i, rule)
                i = i + 1
            elif "name" in rule["rule"] and rule["rule"]["name"] == "redir41x":
                if not inserted:
                    inserted = True
                    for new_rule in rules:
                        print "new rule: " + str(rule)
                        new_port_acl.insert(i, new_rule)
                        i = i + 1
                print "redir41x: " + str(rule)
                new_port_acl.insert(i, rule)
                i = i + 1
            else:
                # insert new rule if not already
                if not inserted:
                    inserted = True
                    for new_rule in rules:
                        print "new rule: " + str(rule)
                        new_port_acl.insert(i, new_rule)
                        i = i + 1
                print "un reck: " + str(rule)
                new_port_acl.insert(i, rule)
                i = i + 1
        print "npa" + str(new_port_acl)
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
            if not (json_data.has_key("mac") and json_data.has_key("user")):
                self.send_error('Invalid form\n')
                return
            self.deauthenticate(self.dot1x_active_file, json_data["mac"],
                                signal.SIGUSR1)
        elif self.path == CAPFLOW:
            #check json has the right information
            if not json_data.has_key("ip"):
                self.send_error('Invalid form\n')
                return
            print "deauth capflow"
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
        nr1 = dict()
        nr1["name"] = user
        nr1["mac"] = mac
        nr1["dl_src"] = DoubleQuotedScalarString(mac)
        nr1["dl_type"] = 0x800
        nr1["nw_dst"] = DoubleQuotedScalarString('8.8.8.8')
        nr1["actions"] = dict()
        nr1["actions"]["allow"] = 0
        nrd1 = dict()
        nrd1["rule"] = nr1

        nr = dict()
        nr["name"] = user
        nr["mac"] = mac
        nr["dl_type"] = 0x800
        nr["dl_src"] = DoubleQuotedScalarString(mac)
        nr["actions"] = dict()
        nr["actions"]["allow"] = 1
        nrd = dict()
        nrd["rule"] = nr

        rules = [nrd1, nrd]
        return rules
       

    def authenticate(self, json_data):
        if self.path == AUTH_PATH:  #request is for dot1xforwarder
            if not (json_data.has_key("mac") and json_data.has_key("user")):
                self.send_error('Invalid form\n')
                return

            #valid request format so new user has authenticated
#            self.write_to_file(self.dot1x_active_file, json_data["mac"],
#                              json_data["user"])
            mac = json_data["mac"]
            user = json_data["user"]
            rules = self.get_users_rules(mac, user)
            self.add_acls(mac, user, rules)

            message = "authenticated new client({}) at MAC: {}\n".format(
                user, mac)
            self.send_signal(signal.SIGHUP)

        else:  #request is for CapFlow
            if not (json_data.has_key("ip") and json_data.has_key("user") and json_data.has_key("mac")):
                self.send_error('Invalid form\n')
                return

            #valid request format so new user has authenticated
#            self.write_to_file(self.capflow_file, json_data["ip"],
#                               json_data["user"])
#            self.send_signal(signal.SIGUSR2)

            mac = json_data["mac"]
            user = json_data["user"]
            ip = json_data["ip"]
            rules = self.get_users_rules(mac, user)
            self.add_acls(mac, user, rules)

            message = "authenticated new client({}) at MAC: {} and ip: {}\n".format(
                user, mac, ip)
            self.send_signal(signal.SIGHUP)
 
        #write response
        self._set_headers(200, 'text/html')
        self.wfile.write(message)
        self.log_message("%s", message)

    def idle(self, json_data):
        if not (json_data.has_key("mac") and json_data.has_key("retrans")):
            self.send_error("Invalid form\n")
            return

        self.write_to_file(self.dot1x_idle_file, json_data["mac"],
                           json_data["retrans"])
#        self.send_signal(signal.SIGUSR1)
        if json_data["retrans"] > 3:
            self._add_cp_acl(json_data["mac"])
            self.send_signal(signal.SIGHUP)

        self._set_headers(200, 'text/html')
        message = "Idle user on {} has been made to use captive portal after {} retransmissions\n".format(
            json_data["mac"], json_data["retrans"])
        self.log_message("%s", message)
        self.wfile.write(message)

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
        self.wfile.write(message)
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
        os.write(fd, string)
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
                self.headers.getheader('content-type'))
        except:
            self.send_error("No content-type header\n")
            return None

        if ctype != 'application/json':
            self.send_error("Data is not a JSON object\n")
            return None
        content_length = int(self.headers.getheader('content-length'))
        data = self.rfile.read(content_length)
        try:
            json_data = json.loads(data)
        except ValueError:
            self.send_error("Not JSON object\n")
            return None

        return json_data

    def send_error(self, error):
        self._set_headers(404, 'text/html')
        self.log_message("Error: %s", error)
        self.wfile.write(error)

    do_GET = do_POST


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    pass


if __name__ == "__main__":
    server = ThreadedHTTPServer(('', 8080), HTTPHandler)
    print "starting server"
    server.serve_forever()
