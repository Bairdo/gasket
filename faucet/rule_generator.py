"""Interface to find and create the Faucet ACL rules, form an external source (file, db)
yaml keys "_authport_*, and values "_usermac_" are currently used for replacing with values as discovered at runtime.
 Switchport (_authport_) that an authenticated user (_usermac_) has authenticated on & with.

TODO maybe make this an interface for yaml or db generator subclasses.
"""
import yaml


class RuleGenerator():

    yaml_file = ""
    conf = None

    def __init__(self, rule_file):

        self.reload(rule_file)

       


    def get_rules(self, username, auth_port_acl, mac):
        """Gets Faucet ACL rules for the specified user.
        Replaces placeholder keys/values as required.
        :param username: The username to find rules for.
        :param auth_port_acl: the port acl name of the port 'username' authenticated on.
        :param mac: mac address of username's machine
        :returns: Dictionary of port_acl names to list of rules.
        """
        rules = dict()

        if username in self.conf["users"].keys():
            for portacl in self.conf["users"][username].keys():
                rules[portacl] = []
                for rule in self.conf["users"][username][portacl]:
                    r = rule["rule"] # should be CommentedMap.
                    for k, v in r.items():
                        if v == "_user-mac_":
                            r[k] = mac
                        if v == "_user-name_":
                            r[k] = username
                    d = dict()
                    d["rule"] = r
                    rules[portacl].append(d)


                if portacl == "_authport_":
                    # rename the port acl to the one the user authenticated on.
                    temp = rules[portacl]
                    del rules[portacl]
                    rules[auth_port_acl] = temp
        print("got rules")
        print(rules)
        return rules

    def reload(self, rule_file):
        """(Re)loads the rule yaml file.
        :param rule_file: path to file.
        """
        self.yaml_file = rule_file
        self.conf = yaml.load(open(rule_file, "r"))

