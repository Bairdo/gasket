 """Configuration parser for authentication controller app."""
# pytype: disable=pyi-error
import socket
import yaml


def validate_ip_address(addr):
    try:
        socket.inet_aton(addr)
    except socket.error:
        raise AssertionError("invalid ip address: %s" % addr)


def validate_port(port):
    assert port is None or 1 <= port <= 64000, "invalid port number: %s" % port


def validate_socket_type(socket_type):
    assert socket_type in ['ping', 'port-forward',
                           'ping-and-portforward'], "invalid socket type: %s" % socket_type


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

        self.hostapd_socket_path = data.get(
            "hostapd", {}).get("socket_path", None)

        self.hostapd_host = None
        self.hostapd_port = None
        if self.hostapd_socket_path is None:
            # can be ipv4, ipv6, or hostname
            self.hostapd_host = data['hostapd']['host']
            self.hostapd_port = data['hostapd']['port']

        self.hostapd_unsol_timeout = data.get(
            "hostapd", {}).get("unsolicited_timeout", None)
        self.hostapd_req_timeout = data.get(
            "hostapd", {}).get("request_timeout", None)
        self.hostapd_req_socket_type = data.get(
            "hostapd", {}).get("request_socket_type", "ping")
        self.hostapd_unsol_socket_type = data.get(
            "hostapd", {}).get("unsolicited_socket_type", "ping")
        self.hostapd_req_bind_port = data.get(
            "hostapd", {}).get("request_bind_port", None)
        self.hostapd_req_bind_address = data.get(
            "hostapd", {}).get("request_bind_address", None)
        self.hostapd_unsol_bind_port = data.get(
            "hostapd", {}).get("unsolicited_bind_port", None)
        self.hostapd_unsol_bind_address = data.get(
            "hostapd", {}).get("unsolicited_bind_address", None)

        self.validate_config()

    def validate_config(self):
        validate_port(self.prom_port)
        validate_port(self.hostapd_req_bind_port)
        validate_port(self.hostapd_unsol_bind_port)

        validate_ip_address(self.faucet_ip)
        if self.hostapd_socket_path is None:
            validate_ip_address(self.hostapd_host)
            validate_port(self.hostapd_port)

        validate_socket_type(self.hostapd_req_socket_type)
        validate_socket_type(self.hostapd_unsol_socket_type)
