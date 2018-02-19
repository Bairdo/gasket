from mininet.topo import Topo
from mininet.link import Intf
from mininet.nodelib import NAT

import os


class Single(Topo):

    def __init__(self):
        Topo.__init__(self)

        sw = self.addSwitch('s1', dpid='000000000000001')

        internet = self.addHost('i0', mac='00:00:00:00:00:02', ip='10.0.0.40')
        self.addLink(sw, internet)

        for i in range(2):
            h = self.addHost(
                'h%d' % i, mac='00:00:00:11:11:%02x' % i, ip=('10.0.0.1%d' % i))
            self.addLink(sw, h)

topos = {'single': (lambda: Single())
         }
