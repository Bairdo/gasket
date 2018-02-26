# Running auth_app with docker & docker-compose

## docker tests

To run the docker based test suite run the following commands as root:

```bash
docker build -t gasket/tests -f Dockerfile.tests .
apparmor_parser -R /etc/apparmor.d/usr.sbin.tcpdump
modprobe openvswitch
docker-compose up -r rabbitmq_server
docker run --network=gasket_control-plane-net --privileged -ti gasket/tests
```


## docker-compose.yaml

This contains an example docker-compose file that can be used in conjunction with a mininet network, to demonstrate 802.1X functionality with Faucet.
It contains 6 containers 'freeradius', 'hostapd', 'faucet', 'gasket', 'rabbitmq_server', 'rabbitmq_adapter'.
- freeradius - is a RADIUS server, see directory docker-compose/freeradius for configuration files.
- hostapd - is the 802.1X authenticator, see directoy docker-compose/hostapd for its configuration file.
- faucet - is the Faucet controller.
- gasket - is the 1X application.
- rabbitmq_server - is a helper container for running a rabbitmq server. gasket connects to this.
- rabbitmq_adapter - is a helper container that publishes events on the Faucet UNIX socket to rabbitmq_server

You will need to setup your network (mininet or real). [see below for mininet example](mininet).

### Running:

Set the following environment variables and start the containers
Note: rabbitmq_adapter uses the volume from faucet, so do not expect to see the directory on the host.
```bash
export FA_RABBIT_HOST=172.222.0.104
export FAUCET_EVENT_SOCK=/var/run/faucet/faucet.sock
docker-compose up freeradius hostapd gasket faucet rabbitmq_server rabbitmq_adapter
```

To kill the gasket container, run the following to tidy up the hostapd control socket connections.
```bash
docker kill --signal 1 gasket_gasket_1
```

At this time the hostapd container is not connected to your mininet network.

Run the following to connect hostapd to s1: (replace '<PROJECT_NAME>' with the name of the top level folder.)
```bash
ovs-docker add-port s1 eth3 <PROJECT_NAME>_hostapd_1 --ipaddress=10.0.0.20/8
```

When the hostapd docker container dies, run the following command to remove the above interface from the ovs switch.
```bash
ovs-docker del-port s1 eth3 <PROJECT_NAME>_hostapd_1
```


Wait a few seconds for the hostapd container to send a ping (so faucet learns where hostapd is) and start hostapd.

## Mininet

A simple topography with 2 end users (h0, h1), and 1 'internet' host (i0)


topo.py:
```python
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
            h = self.addHost('h%d' % i, mac='00:00:00:11:11:%02x' % i, ip=('10.0.0.1%d' % i))
            self.addLink(sw, h)

topos = { 'single': ( lambda: Single())
        }
```


Start mininet:
```bash
mn --topo=single --custom=topo.py --controller=remote,ip=172.222.0.100,port=6653
```
mininet will take several minutes to start as the controller is not running yet.
Alternatively run docker-compose up faucet first.


## TODO
- docker with real network.
