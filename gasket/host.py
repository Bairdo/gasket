"""Represntation of a network (end)host
 TODO Could add another role authorised - rules have been applied.
 TODO Could add another role for hosts that are allowed to be authenticated over many ports.
"""


class Host(object):
    """Stores state related to a (end)host.
    Specifically a MAC. the host could change usernames
    """
    mac = None
    ip = None
    # TODO handle case where host can be on many ports.
    learn_ports = None
    ordered_learn_ports = None
    rule_man = None
    logger = None

    auth_port = None
    authenticated = False
    username = None
    acl_list = None

    def __init__(self, authed, host=None, logger=logger, rule_man=None, mac=None, ip=None,
                 learn_ports=None, ordered_learn_ports=None, learn_port=None,
                 auth_port=None, username=None, acl_list=None):
        self.ordered_learn_ports = []
        self.learn_ports = {}
        if host:
            self.rule_man = host.rule_man
            self.logger = host.logger
            self.mac = host.mac
            self.ip = host.ip
            self.learn_ports = host.learn_ports
            self.ordered_learn_ports = host.ordered_learn_ports
            self.auth_port = host.auth_port
            self.username = host.username
            self.acl_list = host.acl_list
            self.logger.debug('created new host %s from %s', self.__class__, type(host))

        self.authenticated = authed

        if logger:
            self.logger = logger
        if rule_man:
            self.rule_man = rule_man
        if mac:
            self.mac = mac
        if ip:
            self.ip = ip
        if learn_ports:
            self.learn_ports = learn_ports
        if learn_port:
            self.learn_ports[learn_port.number] = learn_port
            self.ordered_learn_ports.append(learn_port.number)
        if auth_port:
            self.auth_port = auth_port
        if username:
            self.username = username
        if acl_list:
            self.acl_list = acl_list

    def get_authing_learn_ports(self):
        """Finds the last learnt port that this host is learnt on that is mode 'access'.
        Returns:
            last learnt port that is mode 'access'.
            Otherwise None
        """
        self.logger.debug('host is on ports %s.\n%s', self.learn_ports, self.ordered_learn_ports)
        for port_no in reversed(self.ordered_learn_ports):
            port = self.learn_ports[port_no]
            if port.auth_mode == 'access':
                return port
        return None

    def __str__(self):
        return "{} mac: {}, ip: {}, learn_ports: {}, ordered_learn_ports {} , auth_port: {}".format(self.__class__,
                                                                                                    self.mac,
                                                                                                    self.ip,
                                                                                                    self.learn_ports,
                                                                                                    self.ordered_learn_ports,
                                                                                                    self.auth_port)


class UnlearntAuthenticatedHost(Host):
    """A host that is not on any openflow port on the network (could be a authport or 'uplink/downlink' port).
    'Authenticated' means the host has done the auth process, (rules may or may not have been applied yet).
    However, can only be authenticated to one port.
    """

    def __init__(self, host=None, logger=None, rule_man=None, mac=None, ip=None,
                 learn_ports=None, ordered_learn_ports=None, learn_port=None,
                 auth_port=None, username=None, acl_list=None):
        super().__init__(True, host=host, logger=logger, rule_man=rule_man, mac=mac, ip=ip,
                         learn_ports=learn_ports, ordered_learn_ports=ordered_learn_ports,
                         learn_port=learn_port, auth_port=auth_port,
                         username=username, acl_list=acl_list)

    def authenticate(self, username, port, acl_list):
        """deauthenticates host from old port.
        Args:
            username (str):
            port (Port): should not be None
            acl_list (list<str>): names of acls to apply.
        """
        assert port is None
        self.acl_list = acl_list

        self.rule_man.deauthenticate(self.username, self.mac)
        # In theory the user could have changed.
        self.username = username
        self.logger.info('ua authed port: %s', port)
        return self

    def deauthenticate(self, port):
        self.rule_man.deauthenticate(self.username, self.mac)

        self.auth_port = None
        self.logger.info('ua deauth should be now uu')
        return UnlearntUnauthenticatedHost(host=self)

    def learn(self, port):
        # add current to learn.
        # if learned port is what authenticated on
        #    authenticate (apply rules)
        # return new LearntAuthedHost.
        self.learn_ports[port.number] = port
        self.ordered_learn_ports.append(port.number)

        self.auth_port = self.get_authing_learn_ports()
        self.logger.info('ua learn port: %s, auth port %s', port, self.auth_port)
        if self.auth_port == port:
            port.add_authed_host(self.mac)

            self.logger.info('ua learn, can apply rules to the port')
            self.rule_man.authenticate(self.username, self.mac,
                                       self.auth_port.datapath.name,
                                       self.auth_port.number, self.acl_list)

        port.add_learn_host(self.mac)
        return LearntAuthenticatedHost(host=self)

    def unlearn(self, port):
        # this shouldnt be possible - already unlearnt
        self.logger.warn('ua cant unlearn if not already learnt')
        return self


class LearntAuthenticatedHost(Host):
    """A host that is on at least on openflow port on the network (could be a authport or 'uplink/downlink' port).
    'Authenticated' means the host has done the auth process, (rules may or may not have been applied yet).
    However, can only be authenticated to one port.
    """

    def __init__(self, host=None, logger=None, rule_man=None, mac=None, ip=None,
                 learn_ports=None, ordered_learn_ports=None, learn_port=None,
                 auth_port=None, username=None, acl_list=None):
        super().__init__(True, host=host, logger=logger, rule_man=rule_man, mac=mac, ip=ip,
                         learn_ports=learn_ports, ordered_learn_ports=ordered_learn_ports,
                         learn_port=learn_port, auth_port=auth_port,
                         username=username, acl_list=acl_list)

    def authenticate(self, username, port, acl_list):
        # host only allowed to auth on single port.
        # deauth on olf.
        # add dp/port to current
        # return self object.

        if port == self.auth_port and username == self.username and acl_list == self.acl_list:
            # if nothing has changed no need to deauth and reload.
            return self

        if self.auth_port:
            self.logger.info('la has authed port already')
            self.auth_port.del_authed_host(self.mac)
        self.rule_man.deauthenticate(self.username, self.mac)

        self.acl_list = acl_list
        self.auth_port = port
        # In theory the user could have changed.
        self.username = username
        self.auth_port.add_authed_host(self.mac)
        self.rule_man.authenticate(self.username, self.mac, self.auth_port.datapath.name,
                                   self.auth_port.number, self.acl_list)
        self.logger.info('la authed auth_port: %s', self.auth_port)
        return self

    def deauthenticate(self, port):
        if self.auth_port:
            self.auth_port.del_authed_host(self.mac)
        self.auth_port = None
        self.rule_man.deauthenticate(self.username, self.mac)
        self.logger.info('la deauth now uu')
        return LearntUnauthenticatedHost(host=self)

    def learn(self, port):
        # add current to learn.
        self.learn_ports[port.number] = port
        self.ordered_learn_ports.append(port.number)
        port.add_learn_host(self.mac)
        self.logger.info('la learn port: %s', port)
        return self

    def unlearn(self, port):
        # remove from current.
        #??do we want to deauth if unlearning from authed port??
        # if dont know where we are
        #   return new unlearntAuthedHost
        # return self object
        port.del_learn_host(self.mac)
        p = self.learn_ports.pop(port.number, None)
        if p is not None:
            self.ordered_learn_ports.remove(port.number)
        if not self.learn_ports:
            self.logger.info('la unlearnt all now ua')
            return UnlearntAuthenticatedHost(host=self)
        self.logger.info('la unlearn still has learn_ports')
        return self


class LearntUnauthenticatedHost(Host):
    """A host that is on at least on openflow port on the network (could be a authport or 'uplink/downlink' port).
    'Unauthenticated' means the host has not done the auth process.
    """

    def __init__(self, host=None, logger=None, rule_man=None, mac=None, ip=None,
                 learn_ports=None, ordered_learn_ports=None, learn_port=None,
                 auth_port=None, username=None, acl_list=None):
        super().__init__(False, host=host, logger=logger, rule_man=rule_man, mac=mac, ip=ip,
                         learn_ports=learn_ports, ordered_learn_ports=ordered_learn_ports,
                         learn_port=learn_port, auth_port=auth_port,
                         username=username, acl_list=acl_list)

    def authenticate(self, username, port, acl_list):
        # authenticate (apply rules)
        # return new LearnAuthedHost.
        self.username = username
        assert port is not None
        self.auth_port = port
        self.acl_list = acl_list
        self.rule_man.authenticate(self.username, self.mac, self.auth_port.datapath.name,
                                   self.auth_port.number, self.acl_list)
        port.add_authed_host(self.mac)
        self.logger.info('lu auth auth_port %s', self.auth_port)
        return LearntAuthenticatedHost(host=self)

    def deauthenticate(self, port):
        # shouldnt be possible
        self.logger.warn('lu deauth shouldnt happen if not already authenticated')
        return self

    def learn(self, port):
        # add current to learn
        port.add_learn_host(self.mac)
        self.learn_ports[port.number] = port
        self.ordered_learn_ports.append(port.number)
        self.logger.info('lu learn port: %s', port)
        return self

    def unlearn(self, port):
        # remove from current.
        # if dont know where we are
        #   return new unlearntAuthedHost
        # return self object
        port.del_learn_host(self.mac)
        p = self.learn_ports.pop(port.number, None)
        if p is not None:
            self.ordered_learn_ports.remove(port.number)
        if not self.learn_ports:
            self.logger.info('lu unlearnt all')
            return UnlearntUnauthenticatedHost(host=self)
        self.logger.info('ul still know some ports')
        return self


class UnlearntUnauthenticatedHost(Host):
    """A host that is not on any  openflow ports on the network.
    'Unauthenticated' means the host has not done the auth process.
    """

    def __init__(self, host=None, logger=None, rule_man=None, mac=None, ip=None,
                 learn_ports=None, ordered_learn_ports=None, learn_port=None,
                 auth_port=None, username=None, acl_list=None):
        super().__init__(False, host=host, logger=logger, rule_man=rule_man, mac=mac, ip=ip,
                         learn_ports=learn_ports, ordered_learn_ports=ordered_learn_ports,
                         learn_port=learn_port, auth_port=auth_port,
                         username=username, acl_list=acl_list)
        if self.learn_ports:
            self.logger.error('learn ports can only be 0')

    def authenticate(self, username, port, acl_list):
        self.acl_list = acl_list

#        self.rule_man.deauthenticate(self.username, self.mac)
        # In theory the user could have changed.
        self.username = username
        self.logger.info('uu auth auth_port %s', self.auth_port)
        return UnlearntAuthenticatedHost(host=self)

    def deauthenticate(self, port):
        # shouldnt be possible
        self.logger.warn('uu shouldnt be able to deauthenticate. not already authenticated')
        return self

    def learn(self, port):
        # add current to learn
        assert port is not None
        self.learn_ports[port.number] = port
        self.ordered_learn_ports.append(port.number)
        port.add_learn_host(self.mac)
        self.logger.info('uu learnt port: %s', port)
        return LearntUnauthenticatedHost(host=self)

    def unlearn(self, port):
        # shouldnt be possible
        self.logger.warn('uu shouldnt be able to unlearn. not already learnt')
        return self
