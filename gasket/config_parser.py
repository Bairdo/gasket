
from gasket.datapath import Datapath
from gasket.hostapd_conf import HostapdConf
from gasket.port import Port


def parse_hostapds(hostapds_conf):
    hostapds = {}
    for hostapd_name, conf in hostapds_conf.items():
        hostapds[hostapd_name] = HostapdConf(hostapd_name, conf)

    return hostapds


def parse_ports(interfaces_conf, dp, logger):
    ports = {}

    for port_key, port_conf in interfaces_conf.items():
        port = Port(port_key, port_conf, dp)
        logger.info('%s', port)
        ports[port_key] = port

    return ports


def parse_datapaths(dps_conf, logger):
    dps = {}
    for dp_key, dp_conf in dps_conf.items():
        assert isinstance(dp_conf, dict)
        dp = Datapath(dp_key, dp_conf.get('dp_id', None), dp_conf)
        dp_id = dp.dp_id
        dps[dp.name] = dp

        interfaces_conf = dp.interfaces
        logger.info('ic: %s', interfaces_conf)
        dp.ports = parse_ports(interfaces_conf, dp, logger)
        logger.info('dp.ports: %s', dp.ports)
    return dps


def add_ports_to_hostapds(hostapds, dps):
    for dp in dps.values():
        for port_num, port in dp.ports.items():
            if port.hostapds:
                for hapd in port.hostapds:
                    hostapds[hapd].add_port(port)


def parse_config(config, logger):

    dps = parse_datapaths(config['dps'], logger)
    hostapds = parse_hostapds(config['hostapds'])

    add_ports_to_hostapds(hostapds, dps)

    return dps, hostapds
