"""Representation of a datapath"""


class Datapath(object):
    """Stores state related to a datapath (switch)
    """
 
    dp_id = None
    dp_name = None

    ports = {}

    def __init__(self, dp_id, dp_name):
        self.dp_id = dp_id
        self.dp_name = dp_name

    def add_port(self, port):
        self.ports[port.number] = port

    def __str__(self):
        return 'Datapath id: %s, name: %s' % (self.dp_id, self.dp_name)
