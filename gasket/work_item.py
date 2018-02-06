

class WorkItem(object):

    mac = None
    hostapd_name = None

    def __init__(self, mac, hostapd_name):
        self.mac = mac
        self.hostapd_name = hostapd_name


class AuthWorkItem(WorkItem):
    """Class that represents an authentication item of work .
    """
    username = None
    acllist = []

    def __init__(self, mac, username, acllist, hostapd_name):
        super().__init__(mac, hostapd_name)
        self.username = username
        self.acllist = acllist


class DeauthWorkItem(WorkItem):
    """Class that represents a deauthentication item of work,
    """
    def __init__(self, mac, hostapd_name):
        super().__init__(mac, hostapd_name)
