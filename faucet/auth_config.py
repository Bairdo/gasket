"""Configuration parser for authentication controller app."""
import yaml

class AuthConfig(object):
    """Structure to hold configuration settings
    """
    # TODO make this inherit from faucet/Conf.py and use the default thing
    def __init__(self, filename):
        data = yaml.load(open(filename, 'r'))

        self.version = data['version']
        self.logger_location = data['logger_location']
        self.listen_port = int(data['listen_port'])

        self.prom_port = int(data['faucet']['prometheus_port'])
        self.faucet_ip = data['faucet']['ip']
        self.prom_url = 'http://{}:{}'.format(self.faucet_ip, self.prom_port)

        self.contr_pid_file = data["files"]["controller_pid"]
        self.faucet_config_file = data["files"]["faucet_config"]
        self.acl_config_file = data['files']['acl_config']

        self.captive_portal_auth_path = data["urls"]["capflow"]
        self.dot1x_auth_path = data["urls"]["dot1x"]
        self.idle_path = data["urls"]["idle"]

        self.dp_port_mode = data["dps"]

        if 'servers' in data:
            servers = data["servers"]

            self.gateways = []
            for gateway in servers["gateways"]:
                self.gateways.append(gateway)

            self.captive_portals = []
            for captive in servers["captive-portals"]:
                self.captive_portals.append(captive)

            # these servers are not currently used by this app.
            self.dot1x_auth_servers = []
            for d1x_server in servers["dot1x-servers"]:
                self.dot1x_auth_servers.append(d1x_server)

            self.dns_servers = []
            for dns_server in servers["dns-servers"]:
                self.dns_servers.append(dns_server)

            self.dhcp_servers = []
            for dhcp_server in servers["dhcp-servers"]:
                self.dhcp_servers.append(dhcp_server)

            self.wins_servers = []
            for wins in servers["wins-servers"]:
                self.wins_servers.append(wins)

        if 'captive-portal' in data:
            self.retransmission_attempts = int(data["captive-portal"]["retransmission-attempts"])

        self.rules = data["auth-rules"]["file"]


