"""Configuration parser for authentication controller app."""
# pytype: disable=pyi-error
import yaml

from gasket import gasket_conf_utils


class AuthConfig(object):
    """Structure to hold configuration settings
    """

    def __init__(self, filename):
        data = yaml.load(open(filename, 'r'), Loader=yaml.CLoader)

        self.version = data['version']
        self.logger_location = data['logger_location']
        log_level = data['logger_level']

        self.logger_level = gasket_conf_utils.get_log_level(log_level)

        self.prom_port = data['faucet']['prometheus_port']
        gasket_conf_utils.validate_port(self.prom_port)

        self.faucet_ip = data['faucet']['ip']
        gasket_conf_utils.validate_ip_address(self.faucet_ip)
        self.prom_url = 'http://{}:{}'.format(self.faucet_ip, self.prom_port)

        self.prom_sleep = data['faucet'].get('prom_sleep', 5)

        self.container_name = data['faucet'].get('container_name', '')

        rabbitmq = data.get('rabbitmq', {})

        self.rabbit_host = rabbitmq.get('host', '')
        self.rabbit_port = rabbitmq.get('port', 5672)


        self.contr_pid_file = data["files"]["controller_pid"]
        self.faucet_config_file = data["files"]["faucet_config"]
        self.acl_config_file = data['files']['acl_config']

        self.base_filename = data['files']['base_config']

        self.dp_port_mode = data["dps"]

        self.gateways = data.get("servers", {}).get("gateways", [])

        self.rules = data["auth-rules"]["file"]

        self.hostapds = data["hostapds"]
