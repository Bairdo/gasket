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
| [TODO](#todo) |


# Introduction

This system is made up of 5 general components as shown in the diagram below: Hosts (end users), authenticator(s), authentication server(s), the Internet, OpenFlow Controller, and an OpenFlow 1.3 capable switch
This has been tested with Ubuntu 16.04 (with [wpa_supplicant](https://w1.fi/wpa_supplicant/) providing 802.1X support).
The **Hosts** must support 802.1X authentication.

The **Authenticator** is a Network Function Virtualisation (NFV) style server
[Hostapd](https://w1.fi/hostapd/) provides the 802.1X authentication.

The **Authentication server** is a RADIUS server.

The **Internet** is the rest of your network, e.g. Gateway, DNS Servers, more Switches & Hosts, e.t.c..

The **Controller** is the [Ryu](osrg.github.io/ryu) OpenFlow Controller, [Faucet](https://github.com/faucetsdn/faucet), and a process (auth_app.py) for managing authentication messages from the authenticator and  configuring Faucet across the network.

The **OpenFlow Switch** is an OpenFlow 1.3 switch we currently use [OpenVSwitch](openvswitch.org).

The diagram below is an example of what we test with, in the future we hope to verify different configurations such as multiple switches managed by a single authenticator & controller, and multiple switch with multiple Authenticator at different switches.
Take note of the link between the Authenticator and the OpenFlow Controller, [see more](#hostapd---controller-link).
This allows the authentication traffic to avoid the dataplane of the switch and therefore any end-user traffic, and allow the Controller to run in out-of-band mode.

```
+-----------+        +--------------+                    +-----------+
|           |        |              |                    |           |
|           |        |Authenticator |                    | OpenFlow  |
|  Internet |        |              +--------------------+Controller |
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

## 'Features' - TODO this needs a better title
- 802.1X in SDN environment.
- Fine grained access control, assign ACL rules that match any 5 tuple (Ethernet src/dst, IP src/dst & transport src/dst port) or any Ryu match field for that matter, not just putting user on a VLAN.
- Authentication Servers can communicate with a RADIUS Server (FreeRADIUS, Cisco ISE, ...).
- Support faucet.yaml 'include' option (see limitations below).
- >25 EAP methods supported - Thanks hostapd.

## Limitations
- .yaml configuration files must have 'dps' & 'acls' as top level (no indentation) objects, and only declared once across all files.
- Weird things may happen if a user moves 'access' port, they should successfully reauthenticate, however they might have issues if a malicious user fakes the authenticated users MAC on the old port (poisoning the MAC-port learning table), and if they (malicious user) were to log off the behaviour is currently 'undefined'.
See [TODO](#todo) for more.


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
When a user sends the EAP-Logoff message they are unauthenticated from the port.

When a user successfully authenticates Access Control List (ACL) rules get applied.
These ACLs are identical to Faucet ACL rule syntax, and can therefore perform any Faucet action such as output, mirror, modify VLANs, ... .
The ACLs can match on any field that Ryu supports (and therefore Faucet), see [Ryu documentation](http://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html#flow-match-structure).
Typically these 'authorisation' rules should include the 'dl_src' with the users MAC address to ensure that the rule gets applied to the user, however if desired this is not necessary, **BUT this could mean that unauthenticated users can use the network!** so do so at your own risk.

#### hostapd - controller link
The hostapd process typically runs on its own server and needs network connectivity to the controller to notify the auth_app process when the state of a user changes.
This connection can be either on the dataplane with appropriate acl's or seperate from the switch's dataplane.

If desired the RADIUS server can be directly connected to the switch (with appropriate ACLs) or through a 'private' network to the hostapd server.

 
### Setup
#### Authentication Server
##### Hostapd
- Get hostapd. Note not official hostapd.
This contains a small number of bugfixes to the control interface socket.

```bash
$ git clone https://github.com/bairdo/hostapd-d1xf.git
$ git checkout faucet-con
```

- Configure the build.
The provided .config should suffice.
However if you wish to modify it, we basically need the wired driver.
CONFIG_CTRL_IFACE=udp shall be used for local udp connections, CONFIG_CTRL_IFACE=udp-remote for udp connections from another machine, or unspecify to use the unix socket if operating hostapd on the same machine as auth_app.
- Build and install.

```
make
sudo make install
```
- hostapd/wired.conf provides the configuration file for hostapd.

Example wired.conf if using hostapd's RADIUS server.
```ini
# udp port to listen on,
# if not using udp use path to unix socket.
# ctrl_interface /var/...
ctrl_interface=udp:8888
interface=eth0
driver=wired
use_pae_group_addr=0

auth_server_addr=<RADIUS SERVER IP>
auth_server_port=<RADIUS SERVER PORT>
auth_server_shared_secret=<RADIUS SERVER SECRET>

acct_server_addr=<ACCOUNTING RADIUS SERVER IP>
acct_server_port=<ACCOUNTING RADIUS SERVER PORT>
acct_server_shared_secret=<ACCOUNTING RADIUS SERVER SECRET>


radius_auth_access_accept_attr=26:12345:1:s
```

(the acct_* may not be required and at this time hostapd will not provide any meaningful accounting statistics to your RADIUS server)

radius_auth_access_accept_attr is a new configuration option that will save the RADIUS Attribute if found in the Access-Accept Message.
This must be set to the Vendor-Specific attribute for Faucet-ACL, if your RADIUS server has multiple Faucet Vendor Attributes.
\<Attribute Id\>:\<Vendor Id\>:\<Vendor Type\>:\<format\>



##### RADIUS Server
- Follow the setup and installation instructions for the RADIUS server of your choice.

- Hostap will authenticate users using the 802.1X methods specified by the RADIUS Server.
If you are using Windows clients EAP-MSCHAPv2 will need to be enabled.

- We (the developer) used FreeRadius during developoment, and Cisco ISE during deployment.
The hostapd integrated eap server does not currently support saving the Access-Accept attributes so is unavailable to use.

- A Vendor-Specific Attribute is required that will return a list of ACL names to apply, the list should probably contain at least one name.

For a simple FreeRADIUS configuration:
dictionary
```ini
...
VENDOR          Faucet          12345
BEGIN-VENDOR    Faucet
    # this could perhaps be a comma seperated list of faucet-like acls to apply. Limited to 255 characters.
    ATTRIBUTE       Faucet-ACL-ID       1       string
END-VENDOR      Faucet
```

users
```ini
...
host1user   Cleartext-Password := "host1pass"
            Reply-Message := "this is a reply message",
            Faucet-ACL-ID := "block-udp,allow-all"
```



#### Controller
##### Faucet

We recommend starting off with the following configuration:

###### faucet.yaml
```yaml
version: 2
vlans:
      100:
            name: vlan100

dps:
      faucet-1:
            dp_id: 1
            hardware: Open vSwitch
            interfaces:
                  1:
                        name: h1
                        native_vlan: 100
                        acl_in: port_faucet-1_1
                        
                  2:
                        name: h2
                        native_vlan: 100
                        acl_in: port_faucet-1_2

                  3:
                        name: h3
                        native_vlan: 100
                        acl_in: port_faucet-1_3
                  4:
                        name: portal
                        native_vlan: 100
                  5:
                        name: internet
                        native_vlan: 100

include:
    - faucet-acls.yaml
```

- Each 'interface' that is to use 802.1X authentication requires:

1. That each 'acl_in' must be in the form 'port\_' + \<DATAPATH NAME\> + '\_' + \<PORT NUMBER\> e.g. for the above configurations 'port_faucet-1_2'.

Note: in the near future this hardcoded requirement will be removed and replaced by a lookup in either the faucet.yaml 'dp' object, or auth.yaml.

###### faucet-acls.yaml

The Faucet ACL configuration must be first generated by rule_manager.py.
rule_manager.py takes an input file that contains the default configuration (when nothing is authenticated) of the ACLs, as well as markers for where to apply rules (for authenticated users) and converts it to a file that Faucet can read containing all the acls.
The input file (shown as base-acls.yaml below) is used during the running of auth_app.py to reconstruct the faucet-acl.yaml when the authentication changes.
It also keeps a record of what rules belong to what username/MAC address so they can be removed on deauthentication.
In the event of a system reboot, as the state is kept here the system can resume without reauthenticating the clients.
The network can be reset.
Resetting should be done via copying the base-no-authed config to base-acls.yaml via your start up script - with docker add this to docker/runauth.sh


The format is similar to vanilla Faucet config.
It must contain a top level structure 'acls' which has children for each port ACL.
The difference from the Faucet config is that the port ACL can in addition to having a single list of rules, can contain multiple lists of rules (in the form of yaml aliases/anchors), and a marker of where to insert new rules.
At a later date it may be beneficial to allow inserting rules at multiple positions within the ACL based on certian conditions (username, RADIUS attributes, groups, ...).
Other ACLs specific to your network/desires can be anywhere within the list, just take note to not place rules conflicting with the 'redirect_1x' rule (e.g. blocking dl_type: 0x888e), and allow some traffic to be redirected by the 'redirect_all' rule so EAPOL-request messages can be sent if the client will not initiate the 802.1X process.


Running:
```bash
python3 rule_manager.py base-acls.yaml faucet-acls.yaml
```
will  produce 2 files, the faucet-acls.yaml for Faucet, and base-acls.yaml-original which is the default ACL configuration.
With:

###### base-acls.yaml
```yaml
# This rule must be near (at) the top of the port ACL.
# It will redirect all 802.1X traffic to the hostpad server that
#  is running on mac address 08:00:27:00:03:02
redirect_1x: &_redirect_1x
    - rule:
        dl_type: 0x888e
        actions:
            allow: 1
            output:
                dl_dst: 08:00:27:00:03:02
# This rule should be near (at) the bottom of the ACLs that it is used in.
# It will redirect all (unauthenticated) traffic to the hostapd server that is running on that mac address.
# Used for getting hostapd to send EAPOL-request messages, to notify the client to start 802.1X.
# Hostapd will actually only repond to dhcp at this time, but they (hostapd) intend to respond to all, with EAPOL-request.
# So the rule can only redirect DHCP if desired.
redirect_all: &_redirect_all
    - rule:
        actions:
            allow: 1
            output:
                dl_dst: 08:00:27:00:03:02 

acls: # acls to keep in the end file.
    port_faucet-1_1:
        - *_redirect_1x
        - authed-rules      # user rules will be inserted at this marker.
        - *_redirect_all

    port_faucet-1_2:
        - *_redirect_1x
        - authed-rules
        - *_redirect_all

    port_faucet-1_3:
        # This acl is equalivant to the above 1 & 2.
        # The acl can contain rules (as below), or anchors to lists of rules ( 1 & 2) if the rules are repeating.
        - rule:
            dl_type: 0x888e
            actions:
                allow: 1
                output:
                    dl_dst: 08:00:27:00:03:02
        - authed-rules
        - rule:
            actions:
                allow: 1
                output:
                    dl_dst: 08:00:27:00:03:02 
```

Should produce this (formatting will likely be different):

###### faucet-acls.yaml
```yaml
acls:
    port_faucet-1_1:
        - rule:
            dl_type: 34958
            actions:
                allow: 1
        - rule:
            actions:
                allow: 1
                dl_dst: 08:00:27:00:03:02
    port_faucet-1_2:
        - rule:
            dl_type: 34958
            actions:
                allow: 1
        - rule:
            actions:
                allow: 1
                dl_dst: 08:00:27:00:03:02
    port_faucet-1_3:
        - rule:
            dl_type: 34958
            actions:
                allow: 1
        - rule:
            actions:
                allow: 1
                dl_dst: 08:00:27:00:03:02
```

These configuration files are based on the network diagram at the top.

- 'port_faucet-1_1' & 'port_faucet-1_2' show the rules that each 802.1X port ACL requires.

- Change the mac address '08:00:27:00:03:02' to the mac address of the server that hostap is running on.
In the future it should be possible to run multiple hostap servers and load balance them via changing the 'actions: dl_dst: <mac_address>' of some of the port ACLs, however auth_app does not currently support multiple control sockets.



###### rules.yaml

TODO talk about how you can have one acl use many acls. or have the radius server do that.

The base directoy contains the file rules.yaml.
rules.yaml contains the rules to apply when a user successfully logs on.
rules.yaml is organised as follows:

- A top-level structure 'acls' which will contain all the ACLs that can be sent from RADIUS.

- Each of these ACLs can have two types lists of ACLs, which both contain lists of ACL rules, this is shown by the 'staff' ACL below.

1. A list named '_authed_port', which applies the child rules to the port that the client authenticated on (as determined at runtime).

2. The name of a specific ACL (in base-acls.yaml) to apply these (the child rules) to.
This will apply regardless of what port the authentication occurs on.

The values '_user-mac_' and '_user-name_' are filled at runtime, with the logged in username and MAC address of the authenticating device.


The keys '_mac_', '_name_' and their value is technically optional, but recomended for most use cases.
The values can be any string, however they are used to identify who the rules belong to so they can be removed when the user logs off, so if they are not set as below when a logoff occurs the rules may not be removed, OR different ones removed (if match a different username).

rules.yaml has support for yaml anchors.
This allows some flexibility in how the acl is defined.


Using rules.yaml below , if Faucet-ACL-Names is set as one of 'student-acl1', or 'student-acl2' or 'block8844,allowipv4,allowarp' the end ACL should be identical.
This means that we can have non singular ACLs defined on our RADIUS server or if that is inconveient just return a single ACL (perhaps a group, vlan, or FIlter-Id) and let rules.yaml generate the more complex ACL.


rules.yaml
```yaml
acls:
    student-acl1:
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
    student-acl2:
        port_ovs-hosts-switch_1:
            - *block8844
            - *allowipv4
            - *allowarp
    
    block8844:
        port_ovs-hosts-switch_1: &block8844
             - rule:
                _name_: _user-name_
                _mac_: _user-mac_
                dl_src: _user-mac_
                dl_type: 0x0800
                nw_dst: 8.8.4.4
                actions:
                    allow: 0           
    allowipv4:
        port_ovs-hosts-switch_1:
            - rule: &allowipv4
                # Faucet Rule
                _name_: _user-name_
                _mac_: _user-mac_
                dl_src: _user-mac_
                dl_type: 0x0800
                actions:
                    allow: 1
    allowarp:
        port_ovs-hosts-switch_1: &allowarp
            - rule:
                _name_: _user-name_
                _mac_: _user-mac_
                dl_src: _user-mac_
                dl_type: 0x0806
                actions:
                    allow: 1
    staff:
        secret_server_acl: # These rules will apply on the ACL named 'secret_server_acl'.
            - rule:
                _name_: _user-name_
                _mac_: _user-mac_
                dl_dst: _user-mac_
                dl_src: 99:99:99:99:99:99 # mac address of server
                actions:
                    allow: 1
        _auth-port_: # These rules will apply on the ACL that belongs to the port the user authenticated on.
            - rule:
                _name_: _user-name_
                _mac_: _user-mac_
                dl_src: _user-mac_
                actions:
                    allow: 1
```

##### auth_app.py
The Faucet repository contains auth_app.py which is used as the 'proxy' between the authentication servers and Faucet.
This must run on the same machine as Faucet, as the SIGHUP signal is used to reload the Faucet configuration.

###### auth.yaml
auth.yaml is the configuration file used by auth_app. Note: the structure and content is subject to change.
```yaml
---
version: 0

logger_location: auth_app.log

faucet:
    prometheus_port: 9244
    ip: 127.0.0.1

files:
    # locations to various files.
    # contr_pid only contains the Process ID (PID) of the Faucet process.
    controller_pid: /etc/faucet/ryu/contr_pid 
    faucet_config: /etc/ryu/faucet/faucet.yaml
    acl_config: /etc/ryu/faucet/faucet-acls.yaml
    base_config: /etc/ryu/faucet/base-acls.yaml

# rules to be applied for a user once authenticated.
auth-rules:
    file: /faucet-src/rules.yaml

# Each port that is to use 802.1X must have 'auth_mode' set to 'access'.
# This is used to identify which port is directly connected to the machine authenticating.
dps:
    faucet-1:
        interfaces:
            1:
                auth_mode: access
            2:
                auth_mode: access
            3:
                auth_mode: access

hostapd:
    host: hostapd
    port: 8888

```


### Running

#### Controller

##### Faucet + auth_app

To start Faucet and auth_app use Docker.auth:
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

# TODO

- allow the use of different modes; 802.1X, Captive Portal, 802.1X with Captive Portal fallback on a port (not necessarily 1X), unauthed vlan.

- Captive Portal.

- hostapd should support using its eap_server instead of an external RADIUS one. 

- Link state events - if port goes down clients on that port should have to reauth.


