"""Represntation of a network (end)host"""

class Host(object):
    """Stores state related to a (end)host.
    """
    mac = None
    ip = None
    # TODO handle case where host can be on many ports.
    dp_name = None
    dp_id = None
    port = None
    vid = None

    authenticated = False
    username = None
    acl_list = None

    def __init__(self, mac, ip, dp_name, dp_id, port, vid, authed=False):
        self.mac = mac
        self.ip = ip
        self.dp_name = dp_name
        self.dp_id = dp_id
        self.port = port
        self.vid = vid
        self.authenticated = authed
