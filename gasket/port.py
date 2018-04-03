"""Representation oif a switch port."""


from gasket import gasket_conf


class Port(gasket_conf.GasketConf):
    """Port that belongs to a datapath.
    Keeps track of hosts learnt and authenticated on it.
    """
    number = None
    dp_id = None
    auth_mode = None
    hostapds = None


    learnt_hosts = set()
    authed_hosts = set()

    datapath = None


    defaults = {
        'number': None,
        'dp_id': None,
        'auth_mode': None,
        'hostapds': None,
    }

    defaults_types = {
        'number': int,
        'dp_id': int,
        'auth_mode': str,
        'hostapds': list,
    }

    def __init__(self, _id, conf, dp):
        """Stores state related to a switch port.
        """
        super(Port, self).__init__(_id, conf, dpid=dp.dp_id)
        self.datapath = dp


    def set_defaults(self):
        super(Port, self).set_defaults()
        self._set_default('number', int(self._id))

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
        return "Port:  %s:%s mode: %s" % (self.dp_id, self.number, self.auth_mode)
