# 801.1X & Captive Portal Authentication with Faucet

This release is a work in progress, and there are bugs.

If you notice something odd, or have any suggestions please create a Github issue or email michael.baird@ecs.vuw.ac.nz

| Table of Contents |
| ------------------- |
| [Introduction](#introduction) |
| [Features](#features) |
| [Limitations](#limitations) |
| [802.1X](#8021x) |
| [802.1X Components](#components) |
| [802.1X Overview](#overview) |
| [802.1X Setup](#setup) |
| [802.1X Running](#running) |
| [Captive Portal](#captive-portal) |
| [TODO](#todo) |


# Introduction

This system is made up of 5 general components as shown in the diagram below: Hosts (end users), authentication server(s), the Internet, OpenFlow Controller, and an OpenFlow 1.3 capable switch.

The **Hosts** must either support 802.1X authentication or have a web browser/be able to make HTTP requests.
This has been tested with Ubuntu 16.04 (with [wpa_supplicant](https://w1.fi/wpa_supplicant/) providing 802.1X support).

The **Authentication server(s)** are Network Function Virtualisation (NFV) style servers.
[Hostapd](https://w1.fi/hostapd/) provides the 802.1X authentication, and a captive portal is provided by [sdn-authenticator-webserver](https://github.com/bairdo/sdn-authenticator-webserver).

The **Internet** provides access to the Internet and at this stage DHCP and DNS servers (which are used by the captive portal).

The **Controller** is the [Ryu](osrg.github.io/ryu) OpenFlow Controller, [Faucet](https://github.com/reannz/faucet), and a HTTP 'server' (auth_app.py) for configuring Faucet across the network.

The **OpenFlow Switch** is an OpenFlow 1.3 switch we currently use [OpenVSwitch](openvswitch.org).
In the future we hope to run on [Allied Telesis ATx930](https:/www.alliedtelesis.com/products/x930-series).

The diagram below is an example of what we have tested with, in the future we hope to verify different configurations such as single switch, and multiple switch with multiple Authentication servers at different switches.
Take note of the link between the Authentication Server and the OpenFlow Controller.
This allows the authentication traffic to avoid the dataplane of the switch and therefore any end-user traffic, and allow the Controller to run in out-of-band mode.

```
+-----------+        +--------------+                    +-----------+
|           |        |              |                    |           |
|           |        |Authentication|                    | OpenFlow  |
|  Internet |        |    Server    +--------------------+Controller |
|           |        |              |                    |           |
|           |        |              |                    |           |
|           |        |              |                    |           |
+-----+-----+        +------+-------+                    +-----+-----+
      |                     |                                  |
      |                     |                                  |
      |                     |                                  |
      |                     |                                  |
+-----+---------------------+----------------------------------+-----+
|                                                                    |
|                                                                    |
|                        OpenFlow Swtich                             |
|                                                                    |
|                                                                    |
+--------------------------------+-----------------------------------+
                                 |
                                 |
                                 |
                                 |
+--------------------------------+-----------------------------------+
|                                                                    |
|                                                                    |
|                           OpenFlow Switch                          |
|                                                                    |
|                                                                    |
+----+--------------+------------+--------------------------+--------+
     |              |            |                          |
+----+---+      +---+---+     +--+---+                   +--+---+
|        |      |       |     |      |                   |      |
|  Host  |      | Host  |     | Host |        ...        | Host |
|        |      |       |     |      |                   |      |
+--------+      +-------+     +------+                   +------+
```

## 'Features'
- 802.1X in SDN environment.
- Captive Portal Fallback when host unresponsive to attempts to authenticate via 802.1X.
- Fine grained access control, assign ACL rules that match any 5 tuple (Ethernet src/dst, IP src/dst & transport src/dst port) or any Ryu match field for that matter, not just putting user on a VLAN.
- Authentication Servers can communicate with a RADIUS Server (FreeRADIUS, Cisco ISE, ...).
- Support faucet.yaml 'include' option (see limitations below).


## Limitations
- .yaml configuration files must have 'dps' & 'acls' as top level (no indentation) objects, and only declared once across all files.
- Weird things may happen if a user moves 'access' port, they should successfully reauthenticate, however they might have issues if a malicious user fakes the authenticated users MAC on the old port (poisoning the MAC-port learning table), and if they (malicious user) were to log off the behaviour is currently 'undefined'.
See [TODO](#todo) for more.

- Each user must have a rule entry, Groups, etc are not supported at this time.
- Captive Portal transmits passwords in cleartext between user and webserver, need to add HTTPS support.

## 802.1X

### Components
- Hostapd
- RADIUS Server (Optional, can use the hostapd integrated one)
- Faucet
- auth_app

### Overview
A user can be in two states authenticated and unauthenticated.
When a user is unauthenticated (default state) all of their traffic is redirected to the hostapd server via a destination MAC address rewrite.
This allows the following:
1. The hostapd process to inform the client that the network is using 802.1X with a EAP-Request message.
2. 802.1X traffic destined to the authenticator should only be received by the hostapd process.
3. One hostpad process to be anywhere on the network.
When a user sends the EAP-Logoff message  they are unauthenticated from the port.

When a user successfully authenticates Access Control List (ACL) rules get applied.
These ACLs are identical to Faucet ACL rule syntax, and can therefore perform any Faucet action such as output, mirror, modify VLANs, ... .
The ACLs can match on any field that Ryu supports (and therefore Faucet), see [Ryu documentation](http://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html#flow-match-structure).
Typically these 'authorisation' rules should include the 'dl_src' with the users MAC address to ensure that the rule gets applied to the user, however if desired this is not necessary, **BUT this could mean that unauthenticated users can use the network!** so do so at your own risk.

The hostapd process typically runs on its own server and has a separate (from the switch's dataplane) network connection to the controller.
This connection is used for HTTP messages to the auth_app process when the state of a user changes.

If desired the RADIUS server can be directly connected to the switch (with appropriate ACLs) or through a 'private' network to the hostapd server.

Once the captive portal is working reliably the hostapd server will be able to assist in providing a 'fallback' to the captive portal for clients who do not want to use 802.1X.
 
### Setup
#### Authentication Server
##### Hostapd
- Get hostapd. Note not official hostapd. This contains modifications to communicate with our Controller HTTPServer.

```bash
$ git clone https://github.com/bairdo/hostapd-d1xf.git
$ git checkout username-fix-2
```

- Configure the build.
The provided .config should suffice. However if you wish to modify it, we basically need the wired driver, and you may also want the integrated RADIUS Server.
- The IP address of the auth_app.py is hardcoded :( the sed command below will replace '10.0.0.2' with '10.0.13.3'.
Replace '10\.0\.13\.3' with the IP address of your faucet's non controlplane link.
- The port number of the auth_app.py is also hardcoded.
Replace 12345 with the port for auth_app.py to listen on.
- Build and install.
```bash
sed -ie 's/10\.0\.0\.2/10\.0\.13\.3/g' hostapd-d1xf/src/eap_server/eap_server.c
sed -ie 's/10\.0\.0\.2/10\.0\.13\.3/g' hostapd-d1xf/src/eapol_auth/eapol_auth_sm.c
sed -ie 's/8080/12345/g' hostapd-d1xf/src/eap_server/eap_server.c && \
sed -ie 's/8080/12345/g' hostapd-d1xf/src/eapol_auth/eapol_auth_sm.c && \
make
sudo make install
```
- hostapd/wired.conf provides the configuration file for hostapd.

Example wired.conf if using hostapd's RADIUS server.
```ini
interface=eth0
driver=wired
logger_stdout=-1
logger_stdout_level=0
ieee8021x=1
eap_reauth_period=3600
use_pae_group_addr=0
eap_server=1
eap_user_file=<PATH TO FILE>/hostapd.eap_user
```

If using the integrated RADIUS server a file containing username, auth-type, password is required. 

See [here for more](http://web.mit.edu/freebsd/head/contrib/wpa/hostapd/hostapd.eap_user)
Example hostapd.eap_user:
```ini
"user"          MD5     "password"
"host110user"   MD5     "host110pass"
"host111user"   MD5     "host111pass"
"host112user"   MD5     "host112pass"
"host113user"   MD5     "host113pass"
"host114user"   MD5     "host114pass"```
```

If not using the integrated RADIUS, the Following are required (the acct_* may not be required and at this time hostapd will not provide any meaningful accounting statistics to your RADIUS server):
```ini
interface=<interface to listen on>
driver=wired
ieee8021x=1
use_pae_group_addr=0
auth_server_addr=<RADIUS SERVER IP>
auth_server_port=<RADIUS SERVER PORT>
auth_server_shared_secret=<RADIUS SERVER SECRET>

acct_server_addr=<ACCOUNTING RADIUS SERVER IP>
acct_server_port=<ACCOUNTING RADIUS SERVER PORT>
acct_server_shared_secret=<ACCOUNTING RADIUS SERVER SECRET>
```

##### RADIUS Server
- Follow the setup and installation instructions for the RADIUS server of your choice.

- Hostap will authenticate users using the 802.1X methods specified by the RADIUS Server.
If you are using Windows clients EAP-MSCHAPv2 will need to be enabled.

- We (the developer) used FreeRadius and the hostap integrated RADIUS server during development, and Cisco ISE during deployment.

#### Controller
##### Faucet
- Get Faucet
```bash
$ git clone https://github.com/bairdo/faucet.git
$ git checkout <branch>
```

We recommend starting off with the following configuration:

###### faucet.yaml
```yaml
version: 2
vlans:
      100:
            name: vlan100

dps:
      ovs-switch:
            dp_id: 1
            hardware: Open vSwitch
            interfaces:
                  1:
                        name: portal
                        native_vlan: 100
                  2:
                        name: gateway
                        native_vlan: 100
                  4:
                        name: hosts
                        native_vlan: 100


      ovs-hosts-switch:
            dp_id: 2
            hardware: Open vSwitch
            interfaces:
                  1:
                        name: h1
                        native_vlan: 100
                        acl_in: port_ovs-hosts-switch_1
                        auth_mode: access
                  2:
                        name: h2
                        native_vlan: 100
                        acl_in: port_ovs-hosts-switch_2
                        auth_mode: access
                  3:
                        name: switch1
                        native_vlan: 100

include:
    - acls.yaml
```

###### acls.yaml
```yaml
acls:
      port_ovs-hosts-switch_1:
          - rule:
                  # This rule must be at the top of the port acl.
                  # It will redirect all 802.1X traffic to the hostap server that
                  #  is running on mac address 08:00:27:00:03:02.
                  name: __1x-redirect__
                  dl_type: 34958
                  actions:
                        allow: 1
          # Once a user has authenticated their rules will be inserted here, below the d1x rule,
          #  with the most recent being nearer the top, and therefore they will have a higher priority on the switch.
          - rule:
                  # This rule should be near the bottom.
                  # It will redirect all traffic to the hostap server that is
                  #  running on mac address 08:00:27:00:03:02.
                  # Used for getting hostap to send EAPOL-request messages, to notify the client to start 802.1X.
                  # I believe hostapd will actually only respond to dhcp at this time, but is intent to respond to all, with EAPOL-request so could add a match for only dhcp.
                  name: __unauth-redirect__
                  actions:
                        allow: 1
                        dl_dst: 08:00:27:00:03:02
      port_ovs-hosts-switch_2:
          - rule:
                  name: __1x-redirect__
                  dl_type: 34958
                  actions:
                        allow: 1
          - rule:
                  name: __unatuh-redirect__
                  actions:
                        allow: 1
                        dl_dst: 08:00:27:00:03:02
```
These configuration files are based on the network diagram at the top.

- Each 'interface' that is to use 802.1X authentication requires two configurations:

1. The key 'auth_mode' must be set with the value 'access'

2. Each 'acl_in' must be in the form 'port\_' + \<DATAPATH NAME\> + '\_' + \<PORT NUMBER\> e.g. for the above configurations 'port_ovs-hosts_switch_2'.

- 'port_ovs-hosts-switch_1' & 'port_ovs-hosts-switch_2' show the rules that each 802.1X port acl requires.
- For the rule 'name' field, please do not use 'd1x' or 'redir41x' as rules which match are treated specially internally.
- Change the mac address '08:00:27:00:03:02' to the mac address of the server that hostap is running on.
It should be possible to run multiple hostap servers and load balance them via changing the 'actions: dl_dst: <mac_address>' of some of the port acls (untested).


###### rules.yaml
The base directoy contains the file rules.yaml.
rules.yaml contains the rules to apply when a user successfully logs on.
The values '_user-mac_' and '_user-name_' are filled at runtime, with the logged in username and MAC address of the authenticating device.


The keys '_mac_', '_name_' and their value is technically optional, but recomended for most use cases.
The values can be any string, however they are used to identify who the rules belong to so they can be removed when the user logs off, so if they are not set as below when a logoff occurs the rules may not be removed, OR different ones removed (if match a different username).

```yaml
users:
    host111user:
        port_ovs-hosts-switch_1: # port_acl to apply rules to
            # '_authport_' is reserved to mean the port that the user authenticated on. Otherwise it should match a portacl.
            # While at it, any port acl keys that begin and start with '_***_' are reserved, by this.
            - rule:
                _name_: _user-name_
                _mac_: _user-mac_
                dl_src: _user-mac_
                dl_type: 0x0800
                nw_dst: 8.8.4.4
                actions:
                    allow: 0
            - rule:
                # Faucet Rule
                _name_: _user-name_
                _mac_: _user-mac_
                dl_src: _user-mac_
                dl_type: 0x0800
                actions:
                    allow: 1
            - rule:
                _name_: _user-name_
                _mac_: _user-mac_
                dl_src: _user-mac_
                dl_type: 0x0806
                actions:
                    allow: 1
```

##### auth_app.py
The faucet repository contains auth_app.py which is used as the 'proxy' between the authentication servers and faucet.
This must run on the same machine as faucet - filesystem locks are used to lock the configuration file and are not available on network shares.

###### auth.yaml
auth.yaml is the configuration file used by auth_app. Note: the structure and content is subject to change.
```yaml
---
version: 0

logger_location: auth_app.log

listen_port: 8080

faucet:
    prometheus_port: 9244
    ip: 127.0.0.1

files:
    # locations to various files.
    # contr_pid only contains the Process ID (PID) of the faucet process.
    controller_pid: contr_pid 
    faucet_config: faucet.yaml
    acl_config: faucet.yaml

urls:
    # HTTP endpoints for auth_app.py
    dot1x: /authenticate/auth

# rules to be applied for a user once authenticated.
auth-rules:
    file: /faucet-src/rules.yaml
```


### Running

#### Controller

##### Faucet + auth_app

To start faucet and auth_app use Docker.auth:
```bash
docker build -t /reannz/faucet-auth -f Dockerfile.auth .
docker run --privileged -v <path-to-config-dir>:/etc/ryu/faucet/ -v <path-to-logging-dir>:/var/log/ryu/faucet/ -p 6653:6653 -p 9244:9244 -p 8080:8080 -ti reannz/faucet-auth
```
Port 6653 is used for OpenFlow, port 9244 is used for Prometheus and 8080 is used by the auth_app - port 9244 may be omitted if you do not need Prometheus.

#### Authentication Server

To start hostapd run as sudo:
```bash
hostapd wired.conf
```

Start the RADIUS server according to your implementations instructions.

## Captive Portal
Not Implemented yet.
### Components
- Captive Portal Webserver
- RADIUS Server
- Faucet
- auth_app

# TODO

- change example config to use only one switch.

- allow user to have their own rules on the port before our user is authenticated ones and after the 1x to hostapd.
For example if all traffic from port is not allowed to go to 8.8.8.8 for what ever reason.

- allow the use of different modes; 802.1X, Captive Portal, 802.1X with Captive Portal fallback on a port (not necessarily 1X), unauthed vlan.

- Captive Portal.

- Allow ACL rules to be applied to any (named) ACL, e.g. logon port 1, but apply rules to port 2 also.
