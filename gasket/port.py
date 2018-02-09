"""Representation of a switch port."""
class Port(object):

    number = None
    datapath = None

    learnt_hosts = {}
    authed_hosts = {}

    def __init__(self, port_no, datapath):
        """Stores state related to a switch port.
        """
        self.number = port_no
        self.datapath = datapath

    def add_learn_host(self, host):
        """Adds a learnt host
        Args:
            host (host.Host): host object that has been learnt
        """
        self.learnt_hosts[host.mac] = host

    def add_authed_host(self, host):
        """Adds a authenticated host
        Args:
            host (host.Host): host object that has authenticated
        """
        self.authed_hosts[host.mac] = host

    def __str__(self):
        return "Port:  %s:%s" % (self.datapath.dp_name, self.number)
