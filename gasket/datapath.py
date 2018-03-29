"""Representation of a datapath"""

from gasket import gasket_conf


class Datapath(gasket_conf.GasketConf):
    """Stores state related to a datapath (switch)
    """

    dp_id = None
    name = None

    interfaces = None


    ports = None

    defaults = {
        'dp_id': None,
        'name': None,
        'interfaces': {},
    }

    defaults_types = {
        'dp_id': int,
        'name': str,
        'interfaces': dict,
    }


    def __init__(self, _id, dp_id, conf):
        super(Datapath, self).__init__(_id, conf, dpid=dp_id)
        self.ports = {}


    def set_defaults(self):
        super(Datapath, self).set_defaults()
        self._set_default('dp_id', self._id)
        self._set_default('name', self._id)


    def add_port(self, port):
        self.ports[port.number] = port

    def __str__(self):
        return 'Datapath id: %s, name: %s' % (self.dp_id, self.dp_name)
