
from gasket.datapath import Datapath
from gasket.hostapd_conf import HostapdConf
from gasket.port import Port


def parse_hostapds(hostapds_conf):
    """
    Args:
        hostapds_conf (dict): top level 'hostapds' dict
    Returns:
        dict of hostapd_name: HostapdConf
    """
    hostapds = {}
    for hostapd_name, conf in hostapds_conf.items():
        hostapds[hostapd_name] = HostapdConf(hostapd_name, conf)

    return hostapds


def parse_ports(interfaces_conf, dp):
    """
    Args:
        interfaces_conf (dict): datapath.interfaces dict
        dp (Datapath): parent datapath object.
    Returns:
        dict of port_key(number) : Port
    """
    ports = {}

    for port_key, port_conf in interfaces_conf.items():
        port = Port(port_key, port_conf, dp)
        ports[port_key] = port

    return ports


def parse_datapaths(dps_conf):
    """
    Args:
        dps_conf (dict): top level dps object
    Returns:
        dict of dp_name : Datapath
    """
    dps = {}
    for dp_key, dp_conf in dps_conf.items():
        assert isinstance(dp_conf, dict)
        dp = Datapath(dp_key, dp_conf.get('dp_id', None), dp_conf)
        dp_id = dp.dp_id
        dps[dp.name] = dp

        interfaces_conf = dp.interfaces
        dp.ports = parse_ports(interfaces_conf, dp)
    return dps


def add_ports_to_hostapds(hostapds, dps):
    """Adds Port objects to the hostapd that is managing them.
    Args:
        hostapds (dict<name:HostapdConf>): hostapd configs to have ports added to.
        dps (dict<name:Datapath>): datapaths with ports.
    """
    for dp in dps.values():
        for port_num, port in dp.ports.items():
            if port.hostapds:
                for hapd in port.hostapds:
                    hostapds[hapd].add_port(port)


def parse_config(config):
    """Parses the gasket configuration.
    Args:
        config (dict): configuration to parse
    Returns:
        {dp_name:Datapath}, {hostapd_name:HostapdConf}
    """
    dps = parse_datapaths(config['dps'])
    hostapds = parse_hostapds(config['hostapds'])

    add_ports_to_hostapds(hostapds, dps)

    return dps, hostapds
