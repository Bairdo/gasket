import logging
import os
import re
import shutil
import signal
import sys
import yaml

from rule_generator import RuleGenerator


def main():
    # pylint: disable=unbalanced-tuple-unpacking
    input_f, output_f = sys.argv[1:3]

    create_base_faucet_acls(input_f, output_f)

    # this is the original, (no one authenticated file). restore to this if necessary.
    shutil.copy2(input_f, input_f + '-orig')

def create_base_faucet_acls(input_f, output_f):
    '''
    Args:
        input_f (str): input filename (base config)
        output_f (str): output filename (faucet-acl.yaml)
    '''
    with open(input_f) as f:
        base = yaml.safe_load(f)
    logging.basicConfig(filename='rule_man_base.log', level=logging.DEBUG)
    final = create_faucet_acls(base, logger=logging)
    write_yaml(final, output_f, True)

def create_faucet_acls(doc, auth_rules=None, logger=None):
    '''Creates a yaml object that represents faucet acls.
    Args:
        doc (yaml object): yaml dict. containing the pre-faucet version of the
                            acls.
        auth_rules (dict): {aclname : list of rule} dictionary containing lists of faucet acl rules to insert. (Optional)
    Returns: yaml object {'acls': ...}
    '''
    final = {}
    final['acls'] = {}
    final_acls = final['acls']

    for acl in list(doc['acls'].items()):
        seq = []
        acl_name = acl[0]
        for obj in acl[1]:
            if isinstance(obj, dict) and 'rule' in obj:
                # rule
                for _, rule in list(obj.items()):
                    new_rule = {}
                    new_rule['rule'] = rule
                    if '_mac_' in rule:
                        del rule['_mac_']
                    if '_name_' in rule:
                        del rule['_name_']
                    seq.append(new_rule)
            elif isinstance(obj, dict):
                #alias
                for name, l in list(obj.items()):
                    for rule in l:
                        r = rule['rule']
                        if '_mac_' in r:
                            del r['_mac_']
                        if '_name_' in r:
                            del r['_name_']
                        seq.append(rule)
            elif isinstance(obj, list):
                for y in obj:
                    if isinstance(y, list):
                        for z in y:
                            if '_mac_' in z['rule']:
                                del z['rule']['_mac_']
                            seq.append(z)
                    if isinstance(y, dict):
                        # list of dicts
                        for _, rule in list(y.items()):
                            new_rule = {}
                            new_rule['rule'] = rule
                            if '_mac_' in rule:
                                del rule['_mac_']
                            if '_name_' in rule:
                                del rule['_name_']
                            seq.append(new_rule)
            elif isinstance(obj, str):
                # this is likey just a 'flag' used to mark position to insert the rules when authed
                if obj == 'authed-rules':
                    continue
                else:
                    print(('illegal string ' + obj))
            else:
                logger.warn('obj not reconised')

        final_acls[acl_name] = seq
    return final

def write_yaml(yml, filename, ignore_aliases=False):
    if ignore_aliases:
        noalias_dumper = yaml.dumper.SafeDumper
        noalias_dumper.ignore_aliases = lambda self, data: True
        with open(filename, 'w') as f:
            yaml.dump(yml, f, default_flow_style=False, Dumper=noalias_dumper)
    else:
        with open(filename, 'w') as f:
            yaml.dump(yml, f, default_flow_style=False)




class RuleManager(object):

    def add_to_base_acls(self, filename, rules, user, logger=None):
        '''Adds rules to the base acl file (and writes).
        Args:
            filename (str);
            rules (dict): {port_s1_1 : list of rules}
        '''
        with open(filename) as f:
            base = yaml.safe_load(f)
        # somehow add the rules to the base where ideally the items in the acl are the pointers.
        # but guess it might not matter, just hurts readability.

        # this is NOT a spelling mistake. this ensures that the auth rules are defined before the use in
        # the port acl. and that the port acl will have the pointer.
        if 'aauth' not in base:
            base['aauth'] = {}

        # TODO make sure the rules don't already exist
        for aclname, acllist in list(rules.items()):
            base['aauth'][aclname + user] = acllist
            base_acl = base['acls'][aclname]
            i = base_acl.index('authed-rules')
            # insert rules above the authed-rules 'flag'. Add 1 for below it. 
            base_acl[i:i] = [{aclname + user: acllist}] # this may not be included as the reference. but instead inserting each.
            # TODO check the rules before i do not already contain the rule about to be inserted.


        # if remove the rule from either the definition or reference, will that remove the other end of the pointer.
        #  because of the way python does the referencing. no it will not.

        # 'rotate' filename - filename.bak, filename.bak.1 this is primiarily for logging, to see how users affect the config.

        # write back to filename 
        write_yaml(base, filename + '.tmp')
        self.backup_file(filename)
        logger.warn('backed up base')
        self.swap_temp_file(filename)
        logger.warn('swapped tmp for base')
        return base

    def authenticate(self, username, mac, switch, port, radius_fields=None, logger=None):
        # get rules to apply
        try:
            if not self.is_authenticated(mac, username, switch, port):
                self.add_to_authed_dict(username, mac, switch, port)
                rules = self.rule_gen.get_rules(username, 'port_' + switch + '_' + str(port), mac)
                # update base
                base = self.add_to_base_acls(self.base_filename, rules, username, logger=logger)
                # update faucet
                final = create_faucet_acls(base, logger=logger)
                write_yaml(final, self.faucet_acl_filename + '.tmp' , True)
                self.backup_file(self.faucet_acl_filename)
                self.swap_temp_file(self.faucet_acl_filename)
                # sighup.
                self.send_signal(signal.SIGHUP)
        except Exception as e:
            logger.critical('except while authenticate')
            logger.exception(e)

    def remove_from_base(self, username, mac, logger=None):
        with open(self.base_filename) as f:
            base = yaml.safe_load(f)
       
        remove = []

        if 'aauth' in base:
            for acl in list(base['aauth'].keys()):
                for  r in base['aauth'][acl]:
                    rule = r['rule']
                    if '_mac_' in rule and '_name_' in rule:
                        if mac == rule['_mac_'] and (username == rule['_name_'] or username == '(null)'):
                            remove.append(acl)
                            break
                    elif '_mac_' in rule and mac == rule['_mac_']:
                        remove.append(acl)
                        break
                    elif '_name_' in rule and username == rule['_name_']:
                        remove.append(acl)
                        break
        removed = False
        for aclname in remove:
            del base['aauth'][aclname]
            removed = True

            for port_acl_name, port_acl_list in list(base['acls'].items()):
                for item in port_acl_list:
                    if isinstance(item, dict):
                        if aclname in item:
                            try:
                                base['acls'][port_acl_name].remove(item)
                                removed = True
                            except Exception as e:
                                logger.exception(e)

        if removed:
            # only need to write it back if something has actually changed.
            write_yaml(base, self.base_filename + '.tmp')
            self.backup_file(self.base_filename)
            self.swap_temp_file(self.base_filename)

        return base, removed

    def deauthenticate(self, username, mac, logger=None):
        try:
            if self.is_authenticated(mac, username):
                self.remove_from_authed_dict(username, mac)
                # update base
                base, changed = self.remove_from_base(username, mac, logger=logger)
                # update faucet only if config has changed
                if changed:
                    final = create_faucet_acls(base, logger=logger)
                    write_yaml(final, self.faucet_acl_filename + '.tmp', True)

                    self.backup_file(self.faucet_acl_filename)
                    self.swap_temp_file(self.faucet_acl_filename)
                    # sighup.
                    self.send_signal(signal.SIGHUP)
        except Exception as e:
            logger.critical('except while authenticate')
            logger.exception(e)

    def __init__(self, config):
        self.config = config

        self.rule_gen = RuleGenerator(self.config.rules)
        self.base_filename = self.config.base_filename
        self.faucet_acl_filename = self.config.acl_config_file
        self.authed_users = {} # {mike: {aa:aa:aa:aa:aa:aa: {faucet-1: {p1: 1. p2: 1}}}}

    def backup_file(self, filename):
        directory = os.path.dirname(filename)
        if directory == '':
            directory = '.'

        filenames = os.listdir(directory)

        string = ''.join(filenames)
        
        matches = re.findall(filename + '.bak', string)

        i = str(len(matches) + 1)

        # backup old current
        shutil.copy2(filename, filename + '.bak' + i)


    def swap_temp_file(self, filename):
        """Renames the temporary file to become the original.
        """
        os.remove(filename)
        # make new tmp the current.
        os.rename(filename + '.tmp', filename)

    def send_signal(self, signal_type):
        ''' Send a signal to the controller to indicate a change in config file
        Args:
            signal_type: SIGUSR1 for dot1xforwarder, SIGUSR2 for CapFlow
        '''
        with open(self.config.contr_pid_file, 'r') as pid_file:
            contr_pid = int(pid_file.read())
            os.kill(contr_pid, signal_type)

    def is_authenticated(self, mac, username=None, switch=None, port=None):
        '''Checks if a username is already authenticated with the MAC address on the switch & port.
        Args:
            username (str)
            mac (str)
            switch (str)
            port (str)
        Returns:
            True if already authenticated. False otherwise.
        '''
        # {mike: {aa:aa:aa:aa:aa:aa: {faucet-1: {p1: 1. p2: 1}}}}
        if username and username != '(null)':
            if username in self.authed_users:
                if mac in self.authed_users[username]:
                    if switch in self.authed_users[username][mac]:
                        if port in self.authed_users[username][mac][switch]:
                            return True
        else:
            for user, dic in list(self.authed_users.items()):
                if mac in list(dic):
                    return True

        return False

    def add_to_authed_dict(self, username, mac, switch, port):
        if username not in self.authed_users:
            self.authed_users[username] = {}
            self.authed_users[username][mac] = {}
            self.authed_users[username][mac][switch] = {}
            self.authed_users[username][mac][switch][port] = 1
        else:
            if mac not in self.authed_users[username]:
                self.authed_users[username][mac] = {}
                self.authed_users[username][mac][switch] = {}
                self.authed_users[username][mac][switch][port] = 1
            else:
                if switch not in self.authed_users[username][mac]:
                    self.authed_users[username][mac][switch] = {}
                    self.authed_users[username][mac][switch][port] = 1
                else:
                    if port not in self.authed_users[username][mac][switch]:
                        self.authed_users[username][mac][switch][port] = 1


    def remove_from_authed_dict(self, username, mac):
        if username and username != '(null)':
            if username in self.authed_users:
                del self.authed_users[username][mac]
        else:
            for user in list(self.authed_users.keys()):
                if mac in user:
                    del user[mac]

def main2():
    base_filename = 'acls.yaml'
    faucet_acl_filename = 'faucet-acl.yaml'
    rule_filename = 'vm-net/rules.yaml'
#    rule_man = RuleManager(rule_filename, base_filename, faucet_acl_filename)


#   rule_man.authenticate('host110user', '33:33:33:33:33:33', 'faucet-1', 1)
#   rule_man.deauthenticate('host110user', '33:33:33:33:33:33')

if __name__ == '__main__':
    main()


# part 1:
#   convert acls.yaml to faucet-acls.yaml
# part 2:
# 

