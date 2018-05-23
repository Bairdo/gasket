from mininet.topo import Topo
from mininet.link import Intf
from mininet.nodelib import NAT

import os


class Single(Topo):

    def __init__(self, no_hosts):
        Topo.__init__(self)

        sw = self.addSwitch('s1', dpid='000000000000001')

        internet = self.addHost('i0', mac='00:00:00:00:00:04', ip='10.0.0.4')
        self.addLink(sw, internet)
        assert no_hosts < 250
        for i in range(no_hosts):
            h = self.addHost(
                'h%d' % i, mac=('00:00:00:11:11:%02x' % (i + 5)), ip=('10.0.0.%d' % (i + 5)))
            self.addLink(sw, h)

topos = {'single': (lambda no_hosts: Single(no_hosts))
        }
