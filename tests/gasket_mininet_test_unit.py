#!/usr/bin/env python

"""Mininet tests for Gasket.
These tests use the https://github.com/faucetsdn/faucet base test classes as the underlying framework."""

# pylint: disable=missing-docstring
# pylint: disable=too-many-arguments

from concurrent import futures
import os
import random
import re
import shutil
import signal
import time
import unittest

import ipaddress
import yaml

from mininet.log import error, output
from mininet.net import Mininet
from mininet.link import Intf

import faucet_mininet_test_base
import faucet_mininet_test_util
import faucet_mininet_test_topo


class GasketTest(faucet_mininet_test_base.FaucetTestBase):
    """Base class for the authentication tests """
    RUN_GASKET = True
    RUN_GAUGE = False
    pids = {}

    max_hosts = 3

    def tearDown(self):
        if self.net is not None:
            host = self.net.hosts[0]
            print "about to kill everything"
            for name, pid in self.pids.iteritems():
                host.cmd('kill ' + str(pid))

            self.net.stop()
        super(GasketTest, self).tearDown()

    def setup_hosts(self, hosts):
        """Create wpa_supplicant config file for each authenticating host.
        Args:
            hosts (list<mininet.host>): host to create config for.
        """
        i = 0
        for host in hosts:
            username = 'hostuser{}'.format(i)
            password = 'hostpass{}'.format(i)
            i += 1

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
            host.cmd('''echo '{0}' > {1}/{2}.conf'''.format(wpa_conf, self.tmpdir, host.defaultIntf()))

            for direction in ['in', 'out']:
                self.start_tcpdump(host, interface=host.defaultIntf(), direction=direction)
 
    def get_users(self):
        """Get the hosts that are users (ie not the portal or controller hosts)
        Returns:
            list<mininet.host>
        """
        users = []
        for host in self.net.hosts:
            if host.name.startswith("h"):
                users.append(host)
        return users

    def find_host(self, hostname):
        """Find a host when given the name
        Args:
            hostname (str): name of host to find.
        """
        for host in self.net.hosts:
            if host.name == hostname:
                return host
        return None

    def logoff_dot1x(self, host, intf=None, netns=None, wait=True):
        if intf is None:
            intf = host.defaultIntf()

        start_reload_count = self.get_configure_count()
        cmd = 'wpa_cli -i %s logoff' % intf
        if netns is not None:
            cmd = 'ip netns exec %s %s' %(netns , cmd)

        host.cmd(cmd)
        if wait:
            for i in range(600):
                end_reload_count = self.get_configure_count()
                if end_reload_count > start_reload_count:
                    break
                time.sleep(0.25)
            self.assertGreater(end_reload_count, start_reload_count)

    def logon_dot1x(self, host, intf=None, netns=None, wait=True):
        """Log on a host using dot1x
        Args:
            host (mininet.host): host to logon.
            intf (str): interface to logon with. if None uses host.defaultIntf()
        """

        if intf is None:
            intf = host.defaultIntf()
        else:
            for direction in ['in', 'out']:
                self.start_tcpdump(host, interface=intf, direction=direction, netns=netns)

        start_reload_count = self.get_configure_count()

        cmd = "wpa_supplicant -i{1} -Dwired -c{0}/{1}.conf -t -d > {0}/wpa_supp-{1}.log 2>&1 &".format(self.tmpdir, intf)
        if netns is None:
            host.cmdPrint(cmd)
        else:
            host.cmdPrint('ip netns exec %s %s' %(netns , cmd))
        self.pids['wpa_supplicant-%s-%s' % (host.name, intf)] = host.lastPid

        # TODO make this loop a function so can be used by relogin.
        # TODO also probably add a more specific regex, and to be able to handle different conditions. e.g. authenticating.

        new_status = self.wpa_cli_status(host, intf)
        for i in range(20):
            if new_status == 'CONNECTING':
                if not wait:
                    print('not waiting')
                    break
            elif new_status == 'HELD' or new_status == 'FAILURE':
                print('logging attemot failed. trying again')
                host.cmdPrint('wpa_cli -i %s logon' % intf)
            elif 'AUTHENTICATED' != new_status:
                break
            time.sleep(1)
            print(host.name, 'login attempt failed. trying again.')
            new_status = self.wpa_cli_status(host, intf=intf)
            print(host.name, new_status)

        if wait:
            end_reload_count = 0
            for i in range(20):
                end_reload_count = self.get_configure_count()
                if end_reload_count > start_reload_count:
                    break
                time.sleep(0.5)
            # this in only an indicator, it could be possible for another host to successfully logon (and reconfigure faucet), thus increasing the counter.
            self.assertGreater(end_reload_count, start_reload_count, 'Host: %s. Intf: %s MAC: %s didn\'t cause config reload. wpa_cli status: %s.' % (host, intf, host.MAC(), new_status))
            self.assertLess(i, 10, 'logon has taken %d to reload. max allowable time 5 seconds' % i)

    def wpa_cli_status(self, host, intf=None):
        if intf is None:
            intf = host.defautlIntf()
        status = host.cmd('wpa_cli -i %s status' % intf)
        
        pattern = 'Supplicant PAE state=\S*'
        for l in status.split('\n'):
            match = re.search(pattern, l)
            if match:
                return match.group(0).split('=')[1]


    def relogon_dot1x(self, host, intf=None, wait=True):
        """Log on a host using dot1x that has already logged on once.
        (tcpdump/wpa_supplicant already started, and has an ip address)
        """
        if intf is None:
            intf = host.defaultIntf()
        start_reload_count = self.get_configure_count()
        old_status = self.wpa_cli_status(host, intf=intf)
        host.cmdPrint('wpa_cli -i %s logon > %s/wpa_cli-%s.log 2>&1' % (intf, self.tmpdir, host.name))

        new_status = self.wpa_cli_status(host, intf)
        for i in range(40):
            if new_status == 'CONNECTING':
                if not wait:
                    break
                time.sleep(1)
            elif new_status == 'AUTHENTICATED':
                time.sleep(10)
                break
            elif new_status == 'AUTHENTICATING':
                time.sleep(1)
            elif new_status == 'HELD':
                # authentication failed for some reason.
                # maybe restart wpa_supplicant?

                host.cmdPrint('wpa_cli note aboutToKillWpaSupp')
                host.cmdPrint('kill %s' % self.pids['wpa_supplicant-%s-%s' % (host.name, host.defaultIntf())])
#                host.cmdPrint('wpa_cli terminate')
#                host.cmdPrint('rm /var/run/wpa_supplicant/%s-%s' % (host.name, host.defaultIntf()))
                time.sleep(1)
                cmd = "wpa_supplicant -i{1} -Dwired -c{0}/{1}.conf -t -f {0}/wpa-{1}.log &".format(self.tmpdir, intf)
                host.cmdPrint(cmd)
                self.pids['wpa_supplicant-%s-%s' % (host.name, host.defaultIntf())] = host.lastPid
                time.sleep(2)
            else:
                time.sleep(1)
                print('unknown wpa status %s' % new_status)
#                host.cmdPrint('wpa_cli -i %s logon' % intf)

            new_status = self.wpa_cli_status(host, intf)
            print(new_status)

        print('relogon took %d loops' % i)
        if wait:
            end_reload_count = 0
            for i in range(20):
                end_reload_count = self.get_configure_count()
                if end_reload_count > start_reload_count:
                    break
                time.sleep(0.5)
            self.assertGreater(end_reload_count, start_reload_count, 'Host: %s. Intf: %s MAC: %s didn\'t cause config reload. wpa_cli status: %s.\nOld Status: %s' % (host, intf, host.MAC(), new_status, old_status))
            self.assertLess(i, 3, 'relogon has taken %d to reload. max allowable time 1.5seconds' % i)

    def fail_ping_ipv4(self, host, dst, retries=1, intf=None, netns=None, print_flag=True):
        """Try to ping to a destination from a host.
        Args:
            host (mininet.host): source host.
            dst (str): destination ip address.
            retries (int): number of attempts.
            intf (str): interface to ping with, if none uses host.defaultIntf()
        """
        for i in range(retries):
            try:
                self.one_ipv4_ping(host, dst, retries=1, require_host_learned=False, intf=intf, netns=netns, print_flag=print_flag)
            except AssertionError:
                return
            time.sleep(1)
        self.fail('host %s + interface %s should not be able to ping %s' % (host.name, intf, dst))

    def check_http_connection(self, host, retries=3):
        """Test the http connectivity by wget-ing a webpage on 10.0.0.2
        Args:
            host (mininet.host): source.
            retries (int): number of attempts.
        Returns:
            True if download successful. False otherwise."""
        for _ in range(retries):
            # pylint: disable=no-member
            result = host.cmd("wget --output-document=- --quiet 10.0.0.2:{}/index.txt".format(self.ws_port))
            if re.search("This is a text file on a webserver", result) is not None:
                return True
        return False


    def run_hostapd(self, host):
        """Compiles and starts the hostapd process.
        Args:
            host (mininet.host): host to run hostapd on.
        """
        # create the hostapd config files
        hostapd_config_cmd = ''
#        for vlan_id in range(3, 3 + self.max_hosts):
        ctrl_iface_dir = '%s/hostapd' % self.tmpdir
        intf = '%s-eth0' % host.name
        host.cmd('''echo "interface={3}\n
ctrl_interface={2}
driver=wired\n
logger_stdout=-1\n
logger_stdout_level=0\n
ieee8021x=1\n
eap_reauth_period=3600\n
use_pae_group_addr=0\n
auth_server_addr=127.0.0.1
auth_server_port=1812
auth_server_shared_secret=SECRET

radius_auth_access_accept_attr=26:12345:1:s"  > {1}/{0}-wired.conf'''.format(host.name, self.tmpdir, ctrl_iface_dir, intf))

        hostapd_config_cmd = hostapd_config_cmd + ' {0}/{1}-wired.conf'.format(self.tmpdir, host.name)
#            host.cmdPrint('ip link add link {0}-eth0 name {0}-eth0.{1} type vlan id {1}'.format(host.name, vlan_id))
#            host.cmd('ip link set {0}-eth0.{1} up'.format(host.name, vlan_id))

        ctrl_iface_path = '%s/%s' % (ctrl_iface_dir, intf)
        self.assertLess(len( ctrl_iface_path), 108, 'hostapd ctrl socket cannot be larger than 108 bytes (including null terminator)\nWas: %d\n%s' % (len(ctrl_iface_path), ctrl_iface_path))

        print 'Starting hostapd ....'
        host.cmd('mkdir %s/hostapd' % self.tmpdir)

        # start hostapd
        host.cmd('hostapd -t -dd {1} > {0}/hostapd.out 2>&1 &'.format(self.tmpdir, hostapd_config_cmd))
        self.pids['hostapd'] = host.lastPid
        
        # TODO is this still required?
        host.cmd('ping -i 0.1 10.0.0.2 &')
        self.pids['p0-ping'] = host.lastPid

    def run_freeradius(self, host):
        host.cmd('freeradius -xx -i 127.0.0.1 -p 1812 -l %s/radius.log' % (self.tmpdir))
        self.pids['freeradius'] = host.lastPid

    def run_internet(self, host):
        host.cmd('echo "This is a text file on a webserver" > index.txt')
        self.ws_port = faucet_mininet_test_util.find_free_port(
            self.ports_sock, self._test_name())

        host.cmd('python -m SimpleHTTPServer {0} &'.format(self.ws_port))

        self.start_dhcp_server(host, gw='10.0.0.2', dns='8.8.8.8')

    def make_dhcp_config(self, filename, intf, gw, dns):
        """Create configuration file for udhcpd.
        Args:
            filename (str): name of config file.
            intf: interface of server to listen on.
            gw (str): ip address of gateway
            dns (str): ip address of dns server
        """
        dns_template = """
default-lease-time 600;
max-lease-time 7200;
option subnet-mask 255.255.255.0;
option broadcast-address 10.0.0.255;
option routers %s;
option domain-name-servers %s;


subnet 10.0.0.0 netmask 255.255.255.0 {
        range 10.0.0.20 10.0.0.250;
        } 
""" % (gw, dns)

        with open(filename, 'w') as f:
            f.write(dns_template)

    def start_dhcp_server(self, host, gw, dns):
        """Start DHCP server (udhcp) on host with specified DNS server
        Args:
            host (mininet.host): host to run udhcp server on.
            intf: interface of server to listen on.
            gw (str): ip address of gateway
            dns (str): ip address of dns server
        """
        print('* Starting DHCP server on', host, 'at', host.IP(), '\n')
        dhcp_config = '/tmp/%s-udhcpd.conf' % host
        self.make_dhcp_config(dhcp_config, host.defaultIntf(), gw, dns)
        host.cmd('touch %s/dhcp.leases' % self.tmpdir)
        host.cmd('dhcpd -d -cf ', dhcp_config, ' ',  host.defaultIntf(),
                ' -lf %s/dhcp.leases' % self.tmpdir,
                 '> %s/%s-dhcp.log 2>&1  &' % (self.tmpdir, host))

    def start_tcpdump(self, host, interface=None, direction=None, expr=None, netns=None):
        if direction is None:
            direction = 'inout'
        if expr is None:
            expr = ''

        if interface is None:
            interface = '%s-eth0' % host.name
            filename = '%s-%s.cap' % (interface, direction)
        elif isinstance(interface, Intf):        
            if interface.name.startswith(host.name):
                filename = '%s-%s.cap' % (interface, direction)
            else:
                filename = '%s-%s-%s.cap' % (host.name, interface, direction)
        else:
            if interface.startswith(host.name):
                filename = '%s-%s.cap' % (interface, direction)
            else:
                filename = '%s-%s-%s.cap' % (host.name, interface, direction)

        tcpdump_args = ' '.join((
            '-s 0',
            '-e',
            '-n',
            '-U',
            '-q',
            '-Q %s' % direction,
            '-i %s' % interface,
            '-w %s/%s' % (self.tmpdir, filename),
            expr,
            '>/dev/null',
            '2>/dev/null',
        ))
        cmd = 'tcpdump %s &' % tcpdump_args
        if netns:
            host.cmd('ip netns exec %s %s' %(netns, cmd))
        else:
            host.cmd(cmd)
        self.pids['tcpdump-%s-%s-%s' % (host.name, interface, direction)] = host.lastPid

    def setup(self):
        super(GasketTest, self).setUp()


class GasketSingleSwitchTest(GasketTest):
    """Base Test class for single switch topology
    """
    ws_port = 0
    clients = []

    N_UNTAGGED = 5
    N_TAGGED = 0
    max_hosts = 3
    CONFIG_GLOBAL = faucet_mininet_test_util.gen_config_global(max_hosts)
    CONFIG_BASE_ACL = faucet_mininet_test_util.gen_base_config(max_hosts)
    CONFIG = faucet_mininet_test_util.gen_config(max_hosts)
    port_map = faucet_mininet_test_util.gen_port_map(N_UNTAGGED + N_TAGGED)

    def setUp(self):
        super(GasketSingleSwitchTest, self).setUp()
       
        self.topo = self.topo_class(
            self.ports_sock, self._test_name(), dpids=[self.dpid], n_tagged=self.N_TAGGED, n_untagged=self.N_UNTAGGED)
       
        # do the base config thing here.
        open(self.tmpdir + '/faucet-acl.yaml', 'w').write(faucet_mininet_test_util.gen_faucet_acl(self.max_hosts) % self.port_map)
        shutil.copytree('/gasket-src/', '%s/gasket-src' % self.tmpdir)
        self.start_net()
        print('network started')
        self.start_programs()
        print('programs started')

    def start_programs(self):
        """Start the authentication controller app, hostapd, dhcp server, 'internet' webserver
        """
        # pylint: disable=unbalanced-tuple-unpacking
        portal, interweb = self.net.hosts[:2]

        # pylint: disable=no-member
        contr_num = int(self.net.controller.name.split('-')[1]) % 255
        self.assertLess(int(contr_num), 255)
        self.net.addLink(
            portal,
            self.net.controller,
            params1={'ip': '192.168.%s.2/24' % contr_num},
            params2={'ip': '192.168.%s.3/24' % contr_num})
        self.one_ipv4_ping(portal, '192.168.%s.3' % contr_num, intf=('%s-eth1' % portal.name))
        portal.setMAC('70:6f:72:74:61:6c', portal.defaultIntf())
        # do not allow the portal to forward ip packets. Otherwise packets redirected to the portal will be forwarded,
        # and effectivley bypass the ACLs.
        portal.cmdPrint("echo '0' > /proc/sys/net/ipv4/ip_forward")

        self.start_tcpdump(self.net.controller)
        self.start_tcpdump(portal, interface='%s-eth0' % portal.name)
        self.start_tcpdump(portal, interface='%s-eth1' % portal.name)
        self.start_tcpdump(portal, interface='lo', expr='udp port 1812 or udp port 1813')
        self.start_tcpdump(interweb)

        self.run_hostapd(portal)
        self.run_freeradius(portal)

        self.run_internet(interweb)

        self.clients = self.net.hosts[2:]
        self.setup_hosts(self.clients)
        time.sleep(10)

class GasketMultiHostPerPortTest(GasketSingleSwitchTest):
    """Config has multiple authenticating hosts on the same port.
    """
    mac_interfaces = {} # {'1': inteface}
    max_vlan_hosts = 2
    def setUp(self):
        super(GasketMultiHostPerPortTest, self).setUp()
        h0 = self.clients[0]

        for i in range(self.max_vlan_hosts):
            mac_intf = '%s-mac%u' % (h0.name, i)

            self.mac_interfaces[str(i)] = mac_intf

            self.add_macvlan(h0, mac_intf)
            netns =  mac_intf + 'ns'
            h0.cmd('ip netns add %s' % netns)
            h0.cmd('ip link set %s netns %s' % (mac_intf, netns))

            h0.cmd('ip netns exec %s ip link set %s up' % (netns, mac_intf))

            username = 'hostuser{}'.format(i)
            password = 'hostpass{}'.format(i)

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
            h0.cmd('''echo '{0}' > {1}/{2}.conf'''.format(wpa_conf, self.tmpdir, mac_intf))

    def tearDown(self):
        h0 = self.clients[0]

        for mac_intf in list(self.mac_interfaces.values()):
            netns = mac_intf + 'ns'
            h0.cmd('ip netns del %s' % netns)
        super(GasketMultiHostPerPortTest, self).tearDown()

    def get_macvlan_ip(self, h, intf):
        '''Get the IP address of a macvlan that is in an netns
        '''
        netns = intf + 'ns'
        cmd = "ip addr show dev %s" % intf
        ip_result = h.cmd('ip netns exec %s %s' % (netns, cmd))
        return re.findall('[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', ip_result)[0]


#@unittest.skip('broken.')
class GasketSingleTwoHostsPerPortTest(GasketMultiHostPerPortTest):

    max_vlan_hosts = 2

    def test_two_hosts_one_port(self):
        '''user0 logs on/off with two devices (MACs) on the same port.
        '''
        h0 = self.clients[0]
        interweb = self.net.hosts[1]

        self.logon_dot1x(h0)
        self.one_ipv4_ping(h0, interweb.IP())
        result = self.check_http_connection(h0)
        self.assertTrue(result)

        mac_intf = self.mac_interfaces['1']
        netns = mac_intf + 'ns'
        self.fail_ping_ipv4(h0, '10.0.0.2', intf=mac_intf, netns=netns)

        self.logon_dot1x(h0, intf=mac_intf, netns=netns)

        self.one_ipv4_ping(h0, interweb.IP(), intf=mac_intf, netns=netns)

        self.logoff_dot1x(h0)
        self.fail_ping_ipv4(h0, '10.0.0.2', retries=5)

        self.relogon_dot1x(h0)
        self.one_ipv4_ping(h0, interweb.IP())

        self.logoff_dot1x(h0)
        self.fail_ping_ipv4(h0, '10.0.0.2')


class GasketMultiHostsBase(GasketSingleSwitchTest):
    
    def logon_logoff(self, host):
        interweb = self.net.hosts[1]
        error_point = 0
        try:
            self.logon_dot1x(host)
            error_point = 1
            self.one_ipv4_ping(host, interweb.IP(), retries=self.LOGON_RETRIES, print_flag=False)
            error_point = 2
            print('%s on' % host.name)
            self.logoff_dot1x(host, wait=False)
            error_point = 3
            # TODO do we want to reduce this retry count (effectivley giving us 15 seconds to stop the hosts traffic)?
            # as close to 0 as possible should be the goal.
            self.fail_ping_ipv4(host, interweb.IP(), retries=self.LOGOFF_RETRIES, print_flag=False)
            error_point = 4
            print('%s off' % host.name)
            self.relogon_dot1x(host)
            error_point = 5
            self.one_ipv4_ping(host, interweb.IP(), retries=self.LOGON_RETRIES, print_flag=False)
            error_point = 6 
            print('%s reon' % host.name)
            return (error_point, '')
        except Exception as e:
            print("Error during method logon_logoff:\n{}".format(e))
            return (error_point, e)

    def test_multi_hosts_parallel(self):
        """Log X different users on on different ports in parallel.
        Then log them all off, and back on again.
        """
        failures = {}
        with futures.ThreadPoolExecutor(max_workers=self.max_hosts) as executor:
            future_to_times = dict ((executor.submit(self.logon_logoff, i), i) for i in self.clients)

            for future in futures.as_completed(future_to_times):
                if future.result()[0] < 6:
                    failures[future_to_times[future]] = future.result()
                h = future_to_times[future]

        self.assertEqual(len(failures), 0, 'the following hosts failed at stages: %s' % failures)

    @unittest.skip('not implemented')
    def test_multi_hosts_random_parallel(self):
        """Log X different users on and off randomly on different ports in parallel.
        """
        # TODO implement.
        # Take a similar appraoch to test_multi_hosts_parallel's ThreadPool.
        # But have the job function randomise weather a host is going to log on, off, or do nothing.
        # Repaat that for each host a number of times.


class GasketSingleTenHostsTest(GasketMultiHostsBase):
    N_UNTAGGED = 12
    max_hosts = N_UNTAGGED - 2

    CONFIG = faucet_mininet_test_util.gen_config(max_hosts)
    CONFIG_GLOBAL = faucet_mininet_test_util.gen_config_global(max_hosts)
    CONFIG_BASE_ACL = faucet_mininet_test_util.gen_base_config(max_hosts)

    port_map = faucet_mininet_test_util.gen_port_map(N_UNTAGGED)

    LOGON_RETRIES = 10
    LOGOFF_RETRIES = 15


class GasketSingleTwentyHostsTest(GasketMultiHostsBase):
    N_UNTAGGED = 22
    max_hosts = N_UNTAGGED - 2

    CONFIG = faucet_mininet_test_util.gen_config(max_hosts)
    CONFIG_GLOBAL = faucet_mininet_test_util.gen_config_global(max_hosts)
    CONFIG_BASE_ACL = faucet_mininet_test_util.gen_base_config(max_hosts)

    port_map = faucet_mininet_test_util.gen_port_map(N_UNTAGGED)

    LOGON_RETRIES = 100
    LOGOFF_RETRIES = 60


class GasketSingle14HostsTest(GasketMultiHostsBase):
    N_UNTAGGED = 16
    max_hosts = N_UNTAGGED - 2

    CONFIG = faucet_mininet_test_util.gen_config(max_hosts)
    CONFIG_GLOBAL = faucet_mininet_test_util.gen_config_global(max_hosts)
    CONFIG_BASE_ACL = faucet_mininet_test_util.gen_base_config(max_hosts)

    port_map = faucet_mininet_test_util.gen_port_map(N_UNTAGGED)

    LOGON_RETRIES = 20
    LOGOFF_RETRIES = 60


class GasketSingleTwoHostsTest(GasketMultiHostsBase):
    N_UNTAGGED = 4
    max_hosts = N_UNTAGGED - 2

    CONFIG = faucet_mininet_test_util.gen_config(max_hosts)
    CONFIG_GLOBAL = faucet_mininet_test_util.gen_config_global(max_hosts)
    CONFIG_BASE_ACL = faucet_mininet_test_util.gen_base_config(max_hosts)

    port_map = faucet_mininet_test_util.gen_port_map(N_UNTAGGED)

    LOGON_RETRIES = 5
    LOGOFF_RETRIES = 10


class GasketSingleTenHostsPerPortTest(GasketMultiHostPerPortTest):

    max_vlan_hosts = 10

    N_UNTAGGED = 5
    max_hosts = N_UNTAGGED - 2

    CONFIG = faucet_mininet_test_util.gen_config(max_hosts)
    CONFIG_GLOBAL = faucet_mininet_test_util.gen_config_global(max_hosts)
    CONFIG_BASE_ACL = faucet_mininet_test_util.gen_base_config(max_hosts)

    port_map = faucet_mininet_test_util.gen_port_map(N_UNTAGGED)


    def test_10_hosts_1_port_seq(self):
        """Log 10 different users on on the same port (using macvlans) sequentially (each should complete before the next starts).
        Then Log them all off. Then back on again. This takes a VERY LONG time to complete >15mins. 
        """
        h0 = self.clients[0]
        h1 = self.clients[1]
        h2 = self.clients[2]
        interweb = self.net.hosts[1]
        self.logon_dot1x(h2)
        self.logon_dot1x(h1)
        self.logon_dot1x(h0)
        self.one_ipv4_ping(h0, interweb.IP(), retries=5)
        self.one_ipv4_ping(h1, interweb.IP(), retries=5)
        h1.intf().updateIP()
        self.one_ipv4_ping(h0, h1.IP(), retries=10)
        mac_intfs = { mac: mac + 'ns' for mac in self.mac_interfaces.values()}
        
        # get each intf going.
        for intf, netns in mac_intfs.items():
            self.logon_dot1x(h0, intf=intf, netns=netns)
            self.one_ipv4_ping(h0, interweb.IP(), intf=intf, retries=10, netns=netns)
        print('first logons complete')

        for intf, netns in mac_intfs.items():
            self.logoff_dot1x(h0, intf=intf, netns=netns)
            self.fail_ping_ipv4(h0, h2.IP(), intf=intf, netns=netns)

        print('logoffs complete')
        self.one_ipv4_ping(h0, interweb.IP())

        for intf, netns in mac_intfs.items():
            self.relogon_dot1x(h0, intf=intf)

        print('relogons complete')
        self.one_ipv4_ping(h0, interweb.IP())
        passed = False
        for i in range(9):
            try:
                for intf, netns in mac_intfs.items():
                    print('ping after relogin')
                    self.one_ipv4_ping(h0, interweb.IP(), intf=intf, retries=1, netns=netns)
                # if it makes it to here all pings have succeeded.
                passed = True
                break
            except AssertionError as e:
                print(e)
                print('try ping again')
        self.assertTrue(passed)


class GasketNoLogOnTest(GasketSingleSwitchTest):
    """Check the connectivity when the hosts are not authenticated"""

    def test_nologon(self):
        """Get the users to ping each other before anyone has authenticated
        """
        users = self.clients
        i = 20
        for user in users:
            i = i + 1
            host = user
            self.start_tcpdump(host)

            # give ip address so ping 'could' work (it won't)
            # TODO is this even needed. will the host not already have an mininet assigned ip?
            user.cmd('ip addr add 10.0.0.%d/24 dev %s' % (i, user.defaultIntf()))

        ploss = self.net.ping(hosts=users, timeout='5')
        self.assertAlmostEqual(ploss, 100)


class GasketSingleDupLogonTest(GasketSingleSwitchTest):
    """Tests various username and MAC address combinations that may or may not result in
    the configuration changing.
    """
    # TODO need to define what the correct behaviour is for these tests.

    def count_username_and_mac(self, mac, username):
        base = yaml.load(open('%s/base-acls.yaml' % self.tmpdir, 'r'))

        count = 0
        for acl_name, acl in list(base['acls'].items()):
            for obj in acl:
                if isinstance(obj, dict) and 'rule' in obj:
                    # normal faucet rule.
                    for _, rule in list(obj.items()):
                        if '_mac_' in rule and '_name_' in rule:
                            if username == rule['_name_'] and mac == rule['_mac_']:
                                count = count + 1
                elif isinstance(obj, dict):
                    # alias
                    for name, l in list(obj.items()):
                        for r in l:
                            r = r['rule']
                            if '_mac_' in r and '_name_' in r:
                                if username == r['_name_'] and mac == r['_mac_']:
                                    count = count + 1
                elif isinstance(obj, list):
                    for y in obj:
                        if isinstance(y, dict):
                            for _, r in list(y.items()):
                                if '_mac_' in r and '_name_' in r:
                                    if username == r['_name_'] and mac == r['_mac_']:
                                        count = count + 1
                        else:
                            # if change the rule_manager to allow lists of other types change this test. 
                            self.assertFalse(True, 'test doesnt support list of type: %s. value: %s' % (type(y), y))
                elif isinstance(obj, str) and obj == 'authed-rules':
                    print('obj is string')
                    pass
                else:
                    # if change rule_manager to allow other types change this test.
                    self.assertFalse(True, 'test doesnt support rule type: %s. value: %s' % (type(obj),obj))
        return count

    def test_same_user_mac_logon_2_same_port(self):
        """Tests that the same username and the same MAC logging onto the same port
        does not add to the base-config file on the second time.
        """
        h0 = self.clients[0]
        interweb = self.net.hosts[1]

        self.logon_dot1x(h0)
        self.one_ipv4_ping(h0, interweb.IP(), retries=5)

        # kill wpa_supplicant so we can attempt to logon again.
        h0.cmd('kill %d' % self.pids['wpa_supplicant-%s-%s' % (h0.name, h0.defaultIntf())])
        time.sleep(1)

        with open('%s/base-acls.yaml' % self.tmpdir, 'rw') as f:
            start_base = f.read()
        try:
            self.logon_dot1x(h0)
        except AssertionError:
            print('logon didnt reload config')
            pass
        else:
            self.assertTrue(False, 'logon should have assertion failed due to config being reloaded, when should be same as before (therefore no reload).')

        with open('%s/auth_app.log' % self.tmpdir, 'r') as auth_log:
            matches = re.findall('authenticated', auth_log.read())

            if matches[0] == 'deauthenticated' and matches[1] == 'authenticated' and matches[2] == 'deauthenticated':
                self.assertFalse(True)
        count = self.count_username_and_mac(h0.MAC(), 'hostuser0')
        self.assertEqual(count, 2)

        with open('%s/base-acls.yaml' % self.tmpdir, 'r') as f:
            end_base = f.read()
        self.assertTrue(end_base != '')
        self.assertTrue(end_base != None)
        self.assertTrue(start_base == end_base)

    def test_same_user_mac_logon_2_diff_port(self):
        """Tests that the same username and the same MAC address can logon on the different ports.
        The system is ambiguous in that the first port to authenticate may or may not be logged off,
        when the second start the authentication process. TODO need to clarify what correct behavoiur should be.
        """
        h0, h1 = self.clients[0:2]
        interweb = self.net.hosts[1]

        self.logon_dot1x(h0)
        self.one_ipv4_ping(h0, interweb.IP(), retries=5)

        h1.setMAC(h0.MAC())

        h1.cmd('sed -i -e s/hostuser1/hostuser0/g %s/%s.conf' % (self.tmpdir, h1.defaultIntf()))
        h1.cmd('sed -i -e s/hostpass1/hostpass0/g %s/%s.conf' % (self.tmpdir, h1.defaultIntf()))

        self.logon_dot1x(h1)
        self.one_ipv4_ping(h1, interweb.IP(), retries=5)

        # TODO 
        # self.one_ipv4_ping(h0, interweb.IP())
        count = self.count_username_and_mac(h0.MAC(), 'hostuser0')
        self.assertGreaterEqual(count, 2)

    def test_same_user_diff_mac_port_logon_2(self):
        """Tests that the same username with a different MAC address can logon on different ports.
        """
        h0, h1 = self.clients[0:2]
        interweb = self.net.hosts[1]

        self.logon_dot1x(h0)
        self.one_ipv4_ping(h0, interweb.IP(), retries=5)

        h1.cmd('sed -i -e s/hostuser1/hostuser0/g %s/%s.conf' % (self.tmpdir, h1.defaultIntf()))
        h1.cmd('sed -i -e s/hostpass1/hostpass0/g %s/%s.conf' % (self.tmpdir, h1.defaultIntf()))

        self.logon_dot1x(h1)
        self.one_ipv4_ping(h1, interweb.IP(), retries=5)

        h0_count = self.count_username_and_mac(h0.MAC(), 'hostuser0')
        h1_count = self.count_username_and_mac(h1.MAC(), 'hostuser0')
        self.assertEqual(h0_count, 2)
        self.assertEqual(h1_count, 2)


class GasketSingleLinkStateTest(GasketSingleSwitchTest):

    def test_dp_link_down_up(self):

        h0 = self.clients[0]
        interweb = self.net.hosts[1]
        # log host on
        self.logon_dot1x(h0)
        self.one_ipv4_ping(h0, interweb.IP(), retries=5)
        self.set_port_down(3)

        h0.cmd('kill %d' % self.pids['wpa_supplicant-%s-%s' % (h0.name, h0.defaultIntf())])
        time.sleep(10)

        self.set_port_up(3)
        # check host cannot ping
        # might need to give h0 a fake ip.
        h0.setIP('10.0.0.99', prefixLen=24)
        self.fail_ping_ipv4(h0, interweb.IP(), retries=5)

        self.logon_dot1x(h0)
        self.one_ipv4_ping(h0, interweb.IP(), retries=5)
