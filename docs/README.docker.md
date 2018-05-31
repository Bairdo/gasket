# Running auth_app with docker & docker-compose

## docker tests

To run the docker based test suite run the following commands as root:

```bash
docker build -t gasket/tests -f Dockerfile.tests .
apparmor_parser -R /etc/apparmor.d/usr.sbin.tcpdump
modprobe openvswitch
docker-compose up -d rabbitmq_server
CONTROL_NETWORK="$(sudo docker network ls |grep control-plane | cut -c 1-12)"
docker run --network=$CONTROL_NETWORK --privileged -ti gasket/tests
```


## docker-compose.yaml

This contains an example docker-compose file that can be used in conjunction with a mininet network, to demonstrate 802.1X functionality with Faucet.
It contains 6 containers 'faucet', 'freeradius', 'gasket', 'hostapd', 'rabbitmq_adapter' & 'rabbitmq_server' .
- faucet - is the OpenFlow controller.
- freeradius - is a RADIUS server, see directory docker-compose/freeradius for configuration files.
- gasket - is the authentication application.
- hostapd - is the 802.1X authenticator, see directoy docker-compose/hostapd for its configuration file.
- rabbitmq_adapter - is a small container for publishing Faucet events (from the faucet UNIX socket) to a rabbitmq server.
- rabbitmq_server - a simple rabbitmq server, gasket will get faucets events from this.

You will need to setup your network (mininet or real). [see below for mininet example](mininet).

### Running:

Start the containers
```bash
export FAUCET_EVENT_SOCK=1
export FA_RABBIT_HOST=<rabbitmq_server IP>
docker-compose up freeradius hostapd gasket faucet rabbitmq_adapter rabbitmq_server
```

To kill the gasket container, (Attempts to shutdown the threads nicely and tidy up the hostapd control socket connections).
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

If restarting the hostapd container the port it connects to on the OVS dp may increase.
There are two options:
1) Use the interface_ranges option on the faucet.yaml
2) Change the ovs-docker script to use 'ofport_request' option when adding the port.
The following diff patch of 'ovs-docker' will allow the --port-request=<port number> flag to be used.

```diff
--- ../ovs-docker-original      2018-06-01 11:36:43.460000000 +1200
+++ /usr/bin/ovs-docker 2018-05-23 16:27:19.616000000 +1200
@@ -90,6 +90,10 @@
                 MTU=`expr X"$1" : 'X[^=]*=\(.*\)'`
                 shift
                 ;;
+            --port-request=*)
+                PORT_REQUEST=`expr X"$1" : 'X[^=]*=\(.*\)'`
+                shift
+                ;;
             *)
                 echo >&2 "$UTIL add-port: unknown option \"$1\""
                 exit 1
@@ -124,8 +128,15 @@
     PORTNAME="${ID:0:13}"
     ip link add "${PORTNAME}_l" type veth peer name "${PORTNAME}_c"
 
+
+    OF_PORT_REQUEST=''
+    if [ -n "$PORT_REQUEST" ]; then
+        OF_PORT_REQUEST=" -- set interface ${PORTNAME}_l ofport_request=$PORT_REQUEST "
+    fi
+
     # Add one end of veth to OVS bridge.
     if ovs_vsctl --may-exist add-port "$BRIDGE" "${PORTNAME}_l" \
+       ${OF_PORT_REQUEST} \
        -- set interface "${PORTNAME}_l" \
        external_ids:container_id="$CONTAINER" \
        external_ids:container_iface="$INTERFACE"; then :; else
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
