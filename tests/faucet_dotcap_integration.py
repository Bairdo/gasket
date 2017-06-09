#!/usr/bin/python
"""
Classes for testing the FAUCET and Authentication
methods (Dot1x and Capflow)
"""
import unittest
import time
import os
import sys
import re
import inspect
import shutil
import tempfile
import threading

from mininet.net import Mininet
from mininet.link import Intf
from mininet.node import OVSSwitch
from mininet.node import RemoteController
from mininet.cli import CLI

import faucet_mininet_test_base
from faucet_mininet_test import FaucetTest
import faucet_mininet_test
from faucet_mininet_test import make_suite
from faucet_mininet_test import parse_args
import faucet_mininet_test_util

#from config_parser import dp_parser

from concurrencytest import ConcurrentTestSuite, fork_for_tests

class FaucetDot1xCapFlowController(RemoteController):
    """A controller that uses the integrated version """

    def __init__(self, name, **kwargs):
        self.ofctl_port = 8084
        RemoteController.__init__(self, name, **kwargs)
    
    def checkListening(self):
        "Overridden to do nothing."
        return


class FaucetAuthenticationTest(faucet_mininet_test.FaucetTest):
    """Base class for the integration tests """

    RUN_GAUGE = False
    script_path = "/faucet-src/tests/dot1x_capflow_scripts" 
    pids = {}

    N_UNTAGGED = 5
    N_TAGGED = 0

    auth_server_port = 0

    def tearDown(self):
        if self.net is not None:
            host = self.net.hosts[0]
            print "about to kill everything"
            os.system('ps aux')
            for name, pid in self.pids.iteritems():
                print name, pid
                host.cmdPrint('kill ' + str(pid))

#            CLI(self.net)
            self.net.stop()

    def setup_host(self, hosts, switch):
        i = 0
        for host in hosts:
#        host = self.net.addHost(
#            "h{0}".format(i),
#                mac="00:00:00:00:00:1{0}".format(i),
#                privateDirs=['/etc/wpa_supplicant'])
#        self.net.addLink(host, switch)
            username = 'host11{0}user'.format(i)
            password = 'host11{0}pass'.format(i)
            i += 1
            host.cmdPrint("ls /etc/wpa_supplicant")

            wpa_conf = '''ctrl_interface=/var/run/wpa_supplicant
ctrl_interface_group=0
eapol_version=2
ap_scan=0
network={
key_mgmt=IEEE8021X
eap=TTLS MD5
identity="%s"
anonymous_identity="%s"
password="%s"
phase1="auth=MD5"
phase2="auth=PAP password=password"
eapol_flags=0
}''' % (username, username, password)
            host.cmdPrint('''echo '{0}' > /etc/wpa_supplicant/{1}.conf'''.format(wpa_conf, host.name))
        


    def get_users(self):
        """
        Get the hosts that are users
        (ie not the portal or controller hosts)
        """
        users = []
        for host in self.net.hosts:
            if host.name.startswith("h"):
                users.append(host)
        return users

    def find_host(self, hostname):
        """Find a host when given the name"""
        for host in self.net.hosts:
            if host.name == hostname:
                return host
        return None

    def logon_capflow(self, host):
        """Log on a host using CapFlow"""
        cmd = "ip addr flush {0}-eth0 && dhclient {0}-eth0 -timeout 5".format(host.name)
        host.cmdPrint(cmd)
        host.cmdPrint("ip route add default via 10.0.12.1")
        host.cmdPrint('echo "nameserver 8.8.8.8" >> /etc/resolv.conf')
        cmd = 'lynx -cmd_script={0}_lynx'.format(
            os.path.join(self.script_path, host.name))
        host.cmdPrint(cmd)

    def logon_dot1x(self, host):
        """Log on a host using dot1x"""

        tcpdump_args = ' '.join((
            '-s 0',
            '-e',
            '-n',
            '-U',
            '-q',
            '-i %s-eth0' % host.name,
            '-w %s/%s-eth0.cap' % (self.tmpdir, host.name),
            '>/dev/null',
            '2>/dev/null',
        ))
        host.cmd('tcpdump %s &' % tcpdump_args)
        self.pids['%s-tcpdump' % host.name] = host.lastPid

        cmd = "wpa_supplicant -i{0}-eth0 -Dwired -c/etc/wpa_supplicant/{0}.conf &".format(host.name)
        print("cmd {}".format(cmd))
        time.sleep(10)
        print(host.cmdPrint(cmd))
        time.sleep(10)
        cmd = "ip addr flush {0}-eth0 && dhcpcd --timeout 60 {0}-eth0".format(host.name)
        print(host.cmdPrint(cmd))
        host.cmdPrint("ip route add default via 10.0.0.2")
        host.cmdPrint('echo "nameserver 8.8.8.8" >> /etc/resolv.conf')

    def fail_ping_ipv4(self, host, dst, retries=3):
        """Try to ping to a destination from a host. This should fail on all the retries"""
        self.require_host_learned(host)
        for _ in range(retries):
            ping_result = host.cmd('ping -c1 %s' % dst)
            print ping_result
            self.assertIsNone(re.search(self.ONE_GOOD_PING, ping_result), ping_result)

    def check_http_connection(self, host, retries=3):
        """Test the http connectivity"""
        for _ in range(retries):
            result = host.cmdPrint("wget --output-document=- --quiet 10.0.0.2:{}/index.txt".format(self.ws_port))
            print 'wgot'
            print result
            if re.search("This is a text file on a webserver",result) is not None:
                return True
        return False

    def run_controller(self, host):
        print 'Starting Controller ....'
#        host.cmdPrint('ryu-manager ryu.app.ofctl_rest faucet.faucet --wsapi-port 8084 &')
#        lastPid = host.lastPid
#        print lastPid
#        os.system('ps a')
#        host.cmdPrint('echo {} > {}/contr_pid'.format(lastPid, self.tmpdir))
#        os.system('ps a')

#        self.pids['faucet'] = lastPid

        # think want to get the auth.yaml, and change the location of the faucet.yaml to be the tmp dir.

        with open('/faucet-src/tests/config/auth.yaml', 'r') as f:
            httpconfig = f.read()

        m = {}
        m['tmpdir'] = self.tmpdir
        m['promport'] = self.prom_port
        m['listenport'] = self.auth_server_port
        host.cmdPrint('echo "%s" > %s/auth.yaml' % (httpconfig % m, self.tmpdir))
        host.cmdPrint('cp -r /faucet-src %s/' % self.tmpdir) 
        print host.cmd('python3.5 %s/faucet-src/faucet/HTTPServer.py --config  %s/auth.yaml > %s/httpserver.txt 2> %s/httpserver.err &' % (self.tmpdir, self.tmpdir, self.tmpdir, self.tmpdir))
        print 'httpserver started'
        self.pids['auth_server'] = host.lastPid 
        print 'httpserver pid'
        print host.lastPid
        print host.cmdPrint('ip addr')

        tcpdump_args = ' '.join((
            '-s 0',
            '-e',
            '-n',
            '-U',
            '-q',
            '-i %s-eth0' % host.name,
            '-w %s/%s-eth0.cap' % (self.tmpdir, host.name),
            '>/dev/null',
            '2>/dev/null',
        ))
        host.cmd('tcpdump %s &' % tcpdump_args)



#        host.cmdPrint('tcpdump -i {0}-eth0 -vv >  {1}/controller-eth0.cap 2>&1 &'.format(host.name, self.tmpdir))
        self.pids['tcpdump'] = host.lastPid


        os.system('ps a')
        os.system('lsof -i tcp')
#        CLI(self.net)
        print 'Controller started.'


    def run_captive_portal(self, host):
        # TODO this was mostly copied from portal.sh so not sure if it actually works here.
        ipt = "# Generated by iptables-save v1.6.0 on Thu Feb 23 20:20:35 2017 \
*nat \
:PREROUTING ACCEPT [0:0] \
:INPUT ACCEPT [2:120] \
:OUTPUT ACCEPT [0:0] \
:POSTROUTING ACCEPT [0:0] \
-A PREROUTING -d 2.2.2.2/32 -i enp0s8 -p tcp -j REDIRECT \
-A PREROUTING -i enp0s8 -p tcp -j REDIRECT \
COMMIT \
# Completed on Thu Feb 23 20:20:35 2017 \
# Generated by iptables-save v1.6.0 on Thu Feb 23 20:20:35 2017 \
*filter \
:INPUT ACCEPT [111042:871714493] \
:FORWARD ACCEPT [9:500] \
:OUTPUT ACCEPT [79360:937635748] \
COMMIT \
# Completed on Thu Feb 23 20:20:35 2017 \
"
        host.cmdPrint('#echo {0}  | iptables-restore' \
                      '#cd /home/$(whoami)/sdn-authenticator-webserver/' \
                      '#nohup java -cp uber-captive-portal-webserver-1.0-SNAPSHOT.jar Main config.yaml > /home/$(whoami)/portal_webserver.out 2>&1 &' \
                      '#echo $! > /home/$(whoami)/portal_webserver_pid.txt')
        self.pids['captive_portal'] = host.lastPid

    def run_hostapd(self, host):
        host.cmdPrint('cp')
        contr_num = self.net.controller.name.split('-')[1]

        print 'Starting hostapd ....'
        host.cmdPrint('''echo "interface={0}-eth0\n
driver=wired\n
logger_stdout=-1\n
logger_stdout_level=0\n
ieee8021x=1\n
eap_reauth_period=3600\n
use_pae_group_addr=0\n
eap_server=1\n
eap_user_file=/root/hostapd-d1xf/hostapd/hostapd.eap_user\n" > {1}/{0}-wired.conf'''.format(host.name , self.tmpdir))

        host.cmdPrint('cp -r /root/hostapd-d1xf/ {}/hostapd-d1xf'.format(self.tmpdir))


#cd /root/hostapd-d1xf/hostapd && \
        print host.cmdPrint('''sed -ie  's/10\.0\.0\.2/192\.168\.{0}\.3/g' {1}/hostapd-d1xf/src/eap_server/eap_server.c && \
sed -ie  's/10\.0\.0\.2/192\.168\.{0}\.3/g' {1}/hostapd-d1xf/src/eapol_auth/eapol_auth_sm.c && \
sed -ie 's/8080/{2}/g' {1}/hostapd-d1xf/src/eap_server/eap_server.c && \
sed -ie 's/8080/{2}/g' {1}/hostapd-d1xf/src/eapol_auth/eapol_auth_sm.c && \
cd {1}/hostapd-d1xf/hostapd && \
make'''.format(contr_num, self.tmpdir, self.auth_server_port))

        print 'made hostapd'
#        host.cmdPrint("""sed -i 's/172\.30\.15\.3/172\.30\.13\.3/g' %s/hostapd""" % (self.tmpdir))
#        host.cmdPrint("""sed -i 's/172\.30\.13\.3/172\.30\.%s\.3/g' %s/hostapd""" % (contr_num, self.tmpdir))
#        host.cmdPrint("""sed -i 's/qwert/{0}/g' {1}/hostapd""".format(self.auth_server_port, self.tmpdir))

        host.cmdPrint('{0}/hostapd-d1xf/hostapd/hostapd -d {0}/{1}-wired.conf > {0}/hostapd.out 2>&1 &'.format(self.tmpdir, host.name))
        self.pids['hostapd'] = host.lastPid

        tcpdump_args = ' '.join((
            '-s 0',
            '-e',
            '-n',
            '-U',
            '-q',
            '-i %s-eth1' % host.name,
            '-w %s/%s-eth1.cap' % (self.tmpdir, host.name),
            '>/dev/null',
            '2>/dev/null',
        ))
        host.cmd('tcpdump %s &' % tcpdump_args)
        self.pids['p1-tcpdump'] = host.lastPid

        tcpdump_args = ' '.join((
            '-s 0',
            '-e',
            '-n',
            '-U',
            '-q',
            '-i %s-eth0' % host.name,
            '-w %s/%s-eth0.cap' % (self.tmpdir, host.name),
            '>/dev/null',
            '2>/dev/null',
        ))
        host.cmd('tcpdump %s &' % tcpdump_args)
        self.pids['p0-tcpdump'] = host.lastPid

        print os.system('ps aux') 

    def makeDHCPconfig(self, filename, intf, gw, dns ):

        DNSTemplate = """
start       10.0.12.10
end     10.0.12.255
option  subnet  255.0.0.0
option  domain  local
option  lease   120  # seconds
"""

        "Create a DHCP configuration file"
        config = (
            'interface %s' % intf,
            DNSTemplate,
            'option router %s' % gw,
            'option dns %s' % dns,
            '' )
        with open( filename, 'w' ) as f:
            f.write( '\n'.join( config ) )

    def startDHCPserver(self, host, gw, dns ):
        "Start DHCP server on host with specified DNS server"
        print( '* Starting DHCP server on', host, 'at', host.IP(), '\n' )
        dhcpConfig = '/tmp/%s-udhcpd.conf' % host
        self.makeDHCPconfig( dhcpConfig, host.defaultIntf(), gw, dns )
        host.cmd( 'udhcpd -f', dhcpConfig,
          '1>/tmp/%s-dhcp.log 2>&1  &' % host )

    def setup(self):
        super(FaucetTest, self).setUp()



class FaucetAuthenticationMultiSwitchTest(FaucetAuthenticationTest):

    def setUp(self):

        print 'mULTIsWITCH test'

        self.net = None
        self.dpid = "1"

#        self.v2_config_hashes, v2_dps = dp_parser('/faucet-src/tests/config/testconfigv2-1x.yaml', 'test_auth')
#        self.v2_dps_by_id = {}
#        for dp in v2_dps:
#            self.v2_dps_by_id[dp.dp_id] = dp
#        self.v2_dp = self.v2_dps_by_id[0x1]

        # copy config file from tests/config to /etc/ryu/faucet/facuet/yaml
        try:
            os.makedirs('/etc/ryu/faucet')
        except:
            pass
        shutil.copyfile("/faucet-src/tests/config/testconfigv2-1x.yaml", "/etc/ryu/faucet/faucet.yaml")

        self.start_net()


    def start_net(self):
        """Start Mininet."""
        os.system('pwd')
        os.system('ls scripts')
        self.net = Mininet(build=False)
        c0 = self.net.addController(
            "c0",
            controller=FaucetDot1xCapFlowController,
            ip='127.0.0.1',
            port=6653,
            switch=OVSSwitch)
        self.contr = c0
        self.run_controller(c0)
 
        switch1 = self.net.addSwitch(
            "s1", cls=OVSSwitch, inband=True, protocols=["OpenFlow13"])
        switch1.start([c0])

        switch2 = self.net.addSwitch(
            "s2", cls=OVSSwitch, inband=False, protocols=["OpenFlow13"])
        self.net.addLink(switch1, switch2)

        portal = self.net.addHost(
            "portal", ip='10.0.12.3/24', mac="70:6f:72:74:61:6c")
        self.net.addLink(portal, switch1)
        self.net.addLink(
            portal,
            c0,
            params1={'ip': '10.0.13.2/24'},
            params2={'ip': '10.0.13.3/24'})

        interweb = self.net.addHost(
            "interweb", ip='10.0.12.1/24', mac="08:00:27:ee:ee:ee")
        self.net.addLink(interweb, switch1)

        interweb.cmdPrint('echo "This is a text file on a webserver" > index.txt')
        interweb.cmdPrint('python -m SimpleHTTPServer 8080 &')

        for i in range(0, 3):
            self.setup_host(i, switch2)
                        
        self.net.build()
        for iface in ['eth0', ]:
            # Connect the switch to the eth0 interface of this host machine
            Intf(iface, node=switch1)

        self.net.start()
        self.startDHCPserver(interweb, gw='10.0.12.1', dns='8.8.8.8')
        print "start portal"
        self.run_hostapd(portal)
        portal.cmdPrint('ip route add 10.0.0.0/8 dev portal-eth0')
#        os.system("ps a")


class FaucetAuthenticationSingleSwitchTest(FaucetAuthenticationTest):

    clients = []
    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
acls:
    port_faucet-1_%(port_3)d:
        - rule:
            _name_: d1x
            actions:
                allow: 1
                dl_dst: 70:6f:72:74:61:6c
            dl_type: 34958
        - rule:
            _name_: redir41x
            actions:
                allow: 1
                output:
                    dl_dst: 70:6f:72:74:61:6c
    port_faucet-1_4:
        - rule:
            _name_: d1x
            actions:
                allow: 1
                dl_dst: 70:6f:72:74:61:6c
            dl_type: 34958
        - rule:
            _name_: redir41x
            actions:
                allow: 1
                output:
                    dl_dst: 70:6f:72:74:61:6c

    port_faucet-1_5:
        - rule:
            _name_: d1x
            actions:
                allow: 1
                dl_dst: 70:6f:72:74:61:6c
            dl_type: 34958
        - rule:
            _name_: redir41x
            actions:
                allow: 1
                output:
                    dl_dst: 70:6f:72:74:61:6c
"""

    CONFIG = """
        interfaces:
            %(port_1)d:
                name: portal
                native_vlan: 100
            %(port_2)d:
                name: gateway
                native_vlan: 100
            %(port_3)d:
                name: host1
                native_vlan: 100
                acl_in: port_faucet-1_%(port_3)d
                auth_mode: access
            %(port_4)d:
                name: host2
                native_vlan: 100
                acl_in: port_faucet-1_%(port_4)d
                auth_mode: access
            %(port_5)d:
                name: host3
                native_vlan: 100
                acl_in: port_faucet-1_%(port_5)d
                auth_mode: access
"""
    def setUp(self):
        super(FaucetAuthenticationTest, self).setUp()
        self.topo = self.topo_class(
            self.ports_sock, dpid=self.dpid, n_tagged=0, n_untagged=5)

        print 'sINGLE sWITCH test'
#        self.net = None
#        self.dpid = "1"

#        self.v2_config_hashes, v2_dps = dp_parser('/faucet-src/tests/config/testconfigv2-1x.yaml', 'test_auth')
#        self.v2_dps_by_id = {}
#        for dp in v2_dps:
#            self.v2_dps_by_id[dp.dp_id] = dp
#        self.v2_dp = self.v2_dps_by_id[0x1]

        # copy config file from tests/config to /etc/ryu/faucet/facuet/yaml
#        try:
#            os.makedirs('/etc/ryu/faucet')
#        except:
#            pass
#        shutil.copyfile("/faucet-src/tests/config/testconfigv2-1x-1s.yaml", "/etc/ryu/faucet/faucet.yaml")
        print 'finding free port'
        port = 0
        while port <=9999:
            port, _ = faucet_mininet_test_util.find_free_port(
                self.ports_sock)
            print 'auth_server_port: ' + str(port)

        self.auth_server_port = port
        self.start_net()
        self.start_programs() 

    def start_programs(self):
        """Start Mininet."""
#        self.net = Mininet(build=False)
#        c0 = self.net.addController(
#            "c0",
#            controller=FaucetDot1xCapFlowController,
#            ip='127.0.0.1',
#            port=6653,
#            switch=OVSSwitch)

        print 'Controller'
        print self.net.controller

 
#        switch1 = self.net.addSwitch(
#            "s1", cls=OVSSwitch, inband=True, protocols=["OpenFlow13"])
#        switch1.start([c0])

        portal, interweb, h0, h1, h2 = self.net.hosts
        lastPid = self.net.controller.lastPid
        print lastPid
#        os.system('ps a')
        self.net.controller.cmdPrint('echo {} > {}/contr_pid'.format(lastPid, self.tmpdir))
        self.pids['faucet'] = lastPid

#            self.net.addHost(
#            "portal", ip='10.0.12.3/24', mac="70:6f:72:74:61:6c")
#        self.net.addLink(portal, switch1)

        contr_num = self.net.controller.name.split('-')[1]

        self.net.addLink(
            portal,
            self.net.controller,
#            params1={'ip': '172.30.13.2/24'},
#            params2={'ip': '172.30.13.3/24'})
#        print 'portal ping controller'
#        print portal.cmdPrint('ping -c5 172.30.13.2')
            params1={'ip': '192.168.%s.2/24' % contr_num},
            params2={'ip': '192.168.%s.3/24' % contr_num})
        print 'portal ping controller'
        print portal.cmdPrint('ping -c5 192.168.%s.3' % contr_num)
        self.run_controller(self.net.controller)

#        interweb = self.net.addHost(
#            "interweb", ip='10.0.12.1/24', mac="08:00:27:ee:ee:ee")
#        self.net.addLink(interweb, switch1)

        interweb.cmdPrint('echo "This is a text file on a webserver" > index.txt')
        self.ws_port, _ = faucet_mininet_test_util.find_free_port(
            self.ports_sock)
        print "ws_port"
        print self.ws_port        
        interweb.cmdPrint('python -m SimpleHTTPServer {0} &'.format(self.ws_port))

 #       for i in range(0, 3):
        hosts = self.net.hosts[2:]

        print 'hosts'
        print self.net.hosts
        print 'clients'
        print hosts
        self.clients = hosts
        self.setup_host(hosts, self.net.switch)
                        

#        self.net.build()
#        self.net.start()
        self.startDHCPserver(interweb, gw='10.0.0.2', dns='8.8.8.8')

        self.run_hostapd(portal)
        portal.cmdPrint('ip route add 10.0.0.0/8 dev portal-eth0')
        


class FaucetAuthenticationCapFlowLogonTest(FaucetAuthenticationMultiSwitchTest):
    """Check if a user can logon successfully using CapFlow"""

    def test_capflowlogon(self):
        """Log on using CapFlow"""
        h0 = self.find_host("h0")
        self.logon_capflow(h0)
        self.one_ipv4_ping(h0, "www.google.co.nz")
        result = self.check_http_connection(h0)
        self.assertTrue(result)


class FaucetAuthenticationSomeLoggedOnTest(FaucetAuthenticationMultiSwitchTest):
    """Check if authenticated and unauthenticated users can communicate"""

    def ping_between_hosts(self, users):
        """Ping between the specified hosts"""
        for user in users:
            user.defaultIntf().updateIP()

        #ping between the authenticated hosts
        ploss = self.net.ping(hosts=users[:2], timeout='5')
        self.assertAlmostEqual(ploss, 0)

        #ping between an authenticated host and an unauthenticated host
        ploss = self.net.ping(hosts=users[1:], timeout='5')
        self.assertAlmostEqual(ploss, 100)
        ploss = self.net.ping(hosts=[users[0], users[2]], timeout='5')
        self.assertAlmostEqual(ploss, 100)

    def QWERTYtest_onlycapflow(self):
        """Only authenticate through CapFlow """
        users = self.get_users()
        self.logon_capflow(users[0])
        self.logon_capflow(users[1])
        cmd = "ip addr flush {0}-eth0 && dhcpcd --timeout 5 {0}-eth0".format(
            users[2].name)
        users[2].cmdPrint(cmd)
        self.ping_between_hosts(users)

    def test_onlydot1x(self):
        """Only authenticate through dot1x"""
        users = self.clients
        self.logon_dot1x(users[0])
        self.logon_dot1x(users[1])
        cmd = "ip addr flush {0}-eth0 && dhcpcd --timeout 5 {0}-eth0".format(
            users[2].name)
        users[2].cmdPrint(cmd)
        self.ping_between_hosts(users)

    def QWERTYtest_bothauthentication(self):
        """Authenicate one user with dot1x and the other with CapFlow"""
        users = self.get_users()
        self.logon_dot1x(users[0])
        self.logon_capflow(users[1])
        cmd = "ip addr flush {0}-eth0 && dhcpcd --timeout 5 {0}-eth0".format(
            users[2].name)
        users[2].cmdPrint(cmd)
        self.ping_between_hosts(users)


class FaucetAuthenticationNoLogOnTest(FaucetAuthenticationMultiSwitchTest):
    """Check the connectivity when the hosts are not authenticated"""

    def test_nologon(self):
        """
        Get the users to ping each other 
        before anyone has authenticated
        """
        users = self.clients
        for user in users:
            cmd = "ip addr flush {0}-eth0 && dhcpcd --timeout 5 {0}-eth0".format(
                user.name)
            user.cmdPrint(cmd)
            user.defaultIntf().updateIP()

        ploss = self.net.ping(hosts=users, timeout='5')
        self.assertAlmostEqual(ploss, 100)


class FaucetAuthenticationDot1XLogonTest(FaucetAuthenticationMultiSwitchTest):
    """Check if a user can logon successfully using dot1x"""

    def test_dot1xlogon(self):
        """Log on using dot1x"""
#        os.system("ps a")
        h0 = self.clients[0]
        interweb = self.net.hosts[1]
        self.logon_dot1x(h0) 
        self.one_ipv4_ping(h0, '10.0.0.2')
        result = self.check_http_connection(h0)
        self.assertTrue(result)


class FaucetAuthenticationDot1XLogoffTest(FaucetAuthenticationMultiSwitchTest):
    """Log on using dot1x and log off"""

    def test_logoff(self):
        """Check that the user cannot go on the internet after logoff"""
        h0 = self.clients[0]
        interweb = self.net.hosts[1]
        self.logon_dot1x(h0)
        self.one_ipv4_ping(h0, '10.0.0.2')
        time.sleep(5)
        result = self.check_http_connection(h0)

        self.assertTrue(result)
        print 'wpa_cli status'
        print h0.cmdPrint('wpa_cli status')
        print h0.cmdPrint("wpa_cli logoff")
        time.sleep(60)
        print 'wpa_cli status'
        print h0.cmdPrint('wpa_cli status')
        self.fail_ping_ipv4(h0, '10.0.0.2')
        result = self.check_http_connection(h0)
        self.assertFalse(result)


class FaucetAuthenticationCapFlowLogoffTest(FaucetAuthenticationMultiSwitchTest):
    """Log on using CapFlow and log off"""

    def test_logoff(self):
        """Check that the user cannot go on the internet after logoff"""
        h0 = self.find_host("h0")
        self.logon_capflow(h0)
        self.one_ipv4_ping(h0, "www.google.co.nz")
        result = self.check_http_connection(h0)
        self.assertTrue(result)
        h0.cmdPrint("timeout 10s curl http://10.0.12.3/loggedout")
        self.fail_ping_ipv4(h0, "www.google.co.nz")
        result = self.check_http_connection(h0)
        self.assertFalse(result)

def start_all_tests():
    """Start all the tests in this file"""
    requested_test_classes, clean, keep_logs, nocheck, serial, excluded_test_classes = parse_args()
    tests = unittest.TestSuite()
    root_tmpdir = tempfile.mkdtemp(prefix='faucet-tests-')
    ports_sock = os.path.join(root_tmpdir, 'ports-server')
    ports_server = threading.Thread(
        target=faucet_mininet_test_util.serve_ports, args=(ports_sock,))
    ports_server.setDaemon(True)
    ports_server.start()
    config = None
    parallel_tests = unittest.TestSuite()
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if requested_test_classes and name not in requested_test_classes:
            continue

        if inspect.isclass(obj) and name.startswith("FaucetAuthentication"):
#            tests.addTest(make_suite(obj, config, root_tmpdir, ports_sock))

            silent_obj = type(obj.__name__ + 'Single', obj.__bases__, dict(obj.__dict__))
            silent_obj.__bases__ = (FaucetAuthenticationSingleSwitchTest,)
            parallel_tests.addTest(make_suite(silent_obj, config, root_tmpdir, ports_sock))
    unittest.TextTestRunner(verbosity=2).run(tests)



    print('running %u tests in parallel and %u tests serial' % (
        parallel_tests.countTestCases(), 0 ))
    results = []
    if parallel_tests.countTestCases():
        max_parallel_tests = min(parallel_tests.countTestCases(), 4)
        parallel_runner = unittest.TextTestRunner(verbosity=255)
        parallel_suite = ConcurrentTestSuite(
            parallel_tests, fork_for_tests(max_parallel_tests))
        results.append(parallel_runner.run(parallel_suite))
    # TODO: Tests that are serialized generally depend on hardcoded ports.
    # Make them use dynamic ports.
#    if single_tests.countTestCases():
#        single_runner = unittest.TextTestRunner(verbosity=255)
#        results.append(single_runner.run(single_tests))
    all_successful = True

    for result in results:
        if not result.wasSuccessful():
            all_successful = False
            print(result.printErrors())


#    os.remove(ports_sock)
#    if not keep_logs and all_successful:
#        shutil.rmtree(root_tmpdir)
    if not all_successful:
        sys.exit(-1)

if __name__ == '__main__':
    start_all_tests()
