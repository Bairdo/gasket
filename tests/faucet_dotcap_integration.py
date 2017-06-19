#!/usr/bin/env python
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


        


class FaucetAuthenticationCapFlowLogonTest(FaucetAuthenticationMultiSwitchTest):
    """Check if a user can logon successfully using CapFlow"""

    def test_capflowlogon(self):
        """Log on using CapFlow"""
        h0 = self.find_host("h0")
        self.logon_capflow(h0)
        self.one_ipv4_ping(h0, "www.google.co.nz")
        result = self.check_http_connection(h0)
        self.assertTrue(result)




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
    ports_sock = faucet_mininet_test.start_port_server(root_tmpdir) 

    config = None
    parallel_tests = unittest.TestSuite()
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if requested_test_classes and name not in requested_test_classes:
            continue

        if inspect.isclass(obj) and name.startswith("FaucetAuthentication"):
#            tests.addTest(make_suite(obj, config, root_tmpdir, ports_sock))

            silent_obj = type(obj.__name__ + 'Single', obj.__bases__, dict(obj.__dict__))
            silent_obj.__bases__ = (FaucetAuthenticationSingleSwitchTest,)
            tests.addTest(make_suite(silent_obj, config, root_tmpdir, ports_sock))
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
