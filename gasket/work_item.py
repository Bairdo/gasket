

class WorkItem(object):

    def __str__(self):
        attrs = vars(self)
        return type(self) + ', '.join('%s: %s' % item for item in attrs.items())

class AuthenticationWorkItem(WorkItem):

    mac = None
    hostapd_name = None

    def __init__(self, mac, hostapd_name):
        self.mac = mac
        self.hostapd_name = hostapd_name


class AuthWorkItem(AuthenticationWorkItem):
    """Class that represents an authentication item of work .
    """
    username = None
    acllist = []

    def __init__(self, mac, username, acllist, hostapd_name):
        super().__init__(mac, hostapd_name)
        self.username = username
        self.acllist = acllist


class DeauthWorkItem(AuthenticationWorkItem):
    """Class that represents a deauthentication item of work,
    """
    def __init__(self, mac, hostapd_name):
        super().__init__(mac, hostapd_name)


class RabbitWorkItem(WorkItem):

    dp_name = None
    dp_id = None

    def __init__(self, dp_name, dp_id):
        self.dp_name = dp_name
        self.dp_id = dp_id


class PortChangeWorkItem(RabbitWorkItem):

    port_no = None
    reason = None
    status = None

    def __init__(self, dp_name, dp_id, port_no, reason, status):
        super().__init__(dp_name, dp_id)

        self.port_no = str(port_no)
        self.reason = reason
        self.status = status

class L2LearnWorkItem(RabbitWorkItem):

    mac = None
    port = None
    vid = None
    ip = None

    def __init__(self, dp_name, dp_id, port, vid, mac, ip):
        super().__init__(dp_name, dp_id)
        self.mac = mac
        #if not isinstance(port, str):
        #    self.port = str(port)
        #else:
        self.port = port
        self.vid = vid
        self.ip = ip
