"""Representation of a switch port."""
class Port(object):

    number = None
    datapath = None
    auth_mode = None

    learnt_hosts = set()
    authed_hosts = set()

    def __init__(self, port_no, datapath, auth_mode):
        """Stores state related to a switch port.
        """
        self.number = port_no
        self.datapath = datapath
        self.auth_mode = auth_mode

    def add_learn_host(self, mac):
        """Adds a learnt host
        Args:
            host (host.Host): host object that has been learnt
        """
        self.learnt_hosts.add(mac)

    def del_learn_host(self, mac):
        """Removes a learnt host
        Args:
            host (host.host): host object that will be unlearnt
        """
        self.learnt_hosts.discard(mac)

    def add_authed_host(self, mac):
        """Adds a authenticated host
        Args:
            host (host.Host): host object that has authenticated
        """
        self.authed_hosts.add(mac)

    def del_authed_host(self, mac):
        """Removes a authenticated host
        Args:
            host (host.host): host object that has been unauthenticated.
        """
        self.authed_hosts.discard(mac)

    def __str__(self):
        return "Port:  %s:%s mode: %s" % (self.datapath.dp_name, self.number, self.auth_mode)
