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

        servers = data["servers"]

        self.gateways = []
        for g in servers["gateways"]:
            self.gateways.append(g)

        self.captive_portals = []
        for cp in servers["captive-portals"]:
            self.captive_portals.append(cp)

        # these servers are not currently used by this app.
        self.dot1x_auth_servers = []
        for d in servers["dot1x-servers"]:
            self.dot1x_auth_servers.append(d)

        self.dns_servers = []
        for d in servers["dns-servers"]:
            self.dns_servers.append(d)

        self.dhcp_servers = []
        for d in servers["dhcp-servers"]:
            self.dhcp_servers.append(d)

        self.wins_servers = []
        for w in servers["wins-servers"]:
            self.wins_servers.append(w)

        self.retransmission_attempts = int(data["captive-portal"]["retransmission-attempts"]) 

        self.rules = data["auth-rules"]["file"]


