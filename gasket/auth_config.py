"""Configuration parser for authentication controller app."""
# pytype: disable=pyi-error
import yaml


class AuthConfig(object):
    """Structure to hold configuration settings
    """

    def __init__(self, filename):
        data = yaml.load(open(filename, 'r'))

        self.version = data['version']
        self.logger_location = data['logger_location']

        self.prom_port = data['faucet']['prometheus_port']
        self.faucet_ip = data['faucet']['ip']
        self.prom_url = 'http://{}:{}'.format(self.faucet_ip, self.prom_port)

        self.contr_pid_file = data["files"]["controller_pid"]
        self.faucet_config_file = data["files"]["faucet_config"]
        self.acl_config_file = data['files']['acl_config']

        self.base_filename = data['files']['base_config']

        self.dp_port_mode = data["dps"]

        self.gateways = data.get("servers", {}).get("gateways", [])

        self.rules = data["auth-rules"]["file"]

        self.hostapds = data["hostapds"]
