"""Handles the construction of the Faucet ACL configuration from the authentication application."""

import logging
import os
import re
import shutil
import signal
import sys
import time
# pytype: disable=pyi-error
import yaml

from rule_generator import RuleGenerator
import auth_app_utils

def main():
    """Create a default base config and the initial Faucet ACL yaml file,
    from a 'base' yaml file.
    """
    # pylint: disable=unbalanced-tuple-unpacking
    input_f, output_f = sys.argv[1:3]

    create_base_faucet_acls(input_f, output_f)

    # this is the original, (no one authenticated file). restore to this if necessary.
    shutil.copy2(input_f, input_f + '-orig')


def create_base_faucet_acls(input_f, output_f):
    """
    Args:
        input_f (str): input filename (base config)
        output_f (str): output filename (faucet-acl.yaml)
    """
    with open(input_f) as f:
        base = yaml.safe_load(f)
    logging.basicConfig(filename='rule_man_base.log', level=logging.DEBUG)
    final = create_faucet_acls(base, logger=logging)
    write_yaml(final, output_f, True)


def create_faucet_acls(doc, auth_rules=None, logger=None):
    """Creates a yaml object that represents faucet acls.
    Args:
        doc (yaml object): yaml dict. containing the pre-faucet version of the
                            acls.
        auth_rules (dict): {aclname : list of rule} dictionary containing lists of faucet acl rules to insert. (Optional)
    Returns: yaml object {'acls': ...}
    """
    final = {}
    final['acls'] = {}
    final_acls = final['acls']

    for acl_name, acl in list(doc['acls'].items()):
        seq = []
        for obj in acl:
            if isinstance(obj, dict) and 'rule' in obj:
                # rule
                for _, rule in list(obj.items()):
                    # TODO is this a pointless for loop? instead do rule = obj['rule']
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
                    else:
                        logger.warning('list of unrecognised objects')
                        logger.warning('child type: %s' % type(y))
                        logger.warning('list object: %s' % obj)
            elif isinstance(obj, str):
                # this is likey just a 'flag' used to mark position to insert the rules when authed
                if obj == 'authed-rules':
                    continue
                else:
                    print(('illegal string ' + obj))
            else:
                logger.warning('Object type %s not recognised' % type(obj))
                logger.warning('Object: %s' % obj)

        final_acls[acl_name] = seq
    return final


def write_yaml(yml, filename, ignore_aliases=False):
    """Writes a yaml object to file.
    Args:
        yml (yaml): yaml object to write to file.
        filename (str)
        ignore_aliases (bool): True if yaml aliases should be removed
                                and object written out in full.
                                False if aliases can be used.
    """
    if ignore_aliases:
        noalias_dumper = yaml.dumper.SafeDumper
        noalias_dumper.ignore_aliases = lambda self, data: True
        with open(filename, 'w') as f:
            yaml.dump(yml, f, default_flow_style=False, Dumper=noalias_dumper)
    else:
        with open(filename, 'w') as f:
            yaml.dump(yml, f, default_flow_style=False)


class RuleManager(object):
    """Handles the construction of the Faucet ACL configuration from the authentication
    application.
    """

    def __init__(self, config):
        self.config = config

        self.rule_gen = RuleGenerator(self.config.rules)
        self.base_filename = self.config.base_filename
        self.faucet_acl_filename = self.config.acl_config_file
        self.authed_users = {} # {mike: {aa:aa:aa:aa:aa:aa: {faucet-1: {p1: 1. p2: 1}}}}
    
    def add_to_base_acls(self, filename, rules, user, mac, logger=None):
        '''Adds rules to the base acl file (and writes).
        Args:
            filename (str);
            rules (dict): {port_s1_1 : list of rules}
            user (str): username
        '''
        with open(filename) as f:
            base = yaml.safe_load(f)
        # somehow add the rules to the base where ideally the items in the acl are the pointers.
        # but guess it might not matter, just hurts readability.

        # this is NOT a spelling mistake. this ensures that the auth rules are defined before the use in
        # the port acl. and that the port acl will have the pointer. At the end of the day it doesn't matter.
        if 'aauth' not in base:
            base['aauth'] = {}

        for aclname, acllist in list(rules.items()):
            base['aauth'][aclname + user + mac] = acllist
            base_acl = base['acls'][aclname]
            i = base_acl.index('authed-rules')
            # insert rules above the authed-rules 'flag'. Add 1 for below it. 
            base_acl[i:i] = [{aclname + user + mac: acllist}] # this may not be included as the reference. but instead inserting each.

        # 'rotate' filename - filename.bak, filename.bak.1 this is primiarily for logging, to see how users affect the config.

        # write back to filename 
        write_yaml(base, filename + '.tmp')
        self.backup_file(filename)
        logger.warn('backed up base')
        self.swap_temp_file(filename)
        logger.warn('swapped tmp for base')
        return base

    def authenticate(self, username, mac, switch, port, radius_fields=None, logger=None):
        """Authenticates a username and MAC address on a switch and port.
        Args:
            username (str)
            mac (str): MAC address
            switch (str): Switch that authentication occured on
            port (str): the 'access port' as configured in 'auth.yaml'
        Returns: 
            True if rules are found and faucet reloads or already authenticated. False otherwise.
        """
        # get rules to apply
        if not self.is_authenticated(mac, username, switch, port):
            self.add_to_authed_dict(username, mac, switch, port)
            rules = self.rule_gen.get_rules(username, 'port_' + switch + '_' + str(port), mac)
            # update base
            base = self.add_to_base_acls(self.base_filename, rules, username, mac, logger=logger)
            # update faucet
            final = create_faucet_acls(base, logger=logger)
            write_yaml(final, self.faucet_acl_filename + '.tmp' , True)
            self.backup_file(self.faucet_acl_filename)
            self.swap_temp_file(self.faucet_acl_filename)
            # sighup.
            start_count = self.get_faucet_reload_count()
            self.send_signal(signal.SIGHUP)
            logger.info('auth signal sent.')
            for i in range(400):
                end_count = self.get_faucet_reload_count()
                if end_count > start_count:
                    logger.info('auth - faucet has reloaded.')
                    return True
                time.sleep(0.05)
                logger.info('auth - waiting for faucet to process sighup config reload. %d' % i)
            logger.error('auth - faucet did not process sighup within 30 seconds. 0.05 * 400')
            return False
        return True

    def get_faucet_reload_count(self):
        txt = auth_app_utils.scrape_prometheus(self.config.prom_url)
        for l in txt.splitlines():
            if l.startswith('faucet_config_reload_requests'):
                return int(float(l.split()[1]))
        return 0

    def remove_from_base(self, username, mac, logger=None):
        """Removes rules that have matching mac= _mac_ and username=_name_
        If both _mac_ and _name_ exist in the rule, both must match
        If only one of _mac_ or _name_ is exist, only one must match.
        Args:
            username (str)
            mac (str): MAC address
        """
        with open(self.base_filename) as f:
            base = yaml.safe_load(f)
        
        logger.info(base)
        remove = []

        if 'aauth' in base:
            for acl in list(base['aauth'].keys()):
                logger.debug('aauth acl')
                logger.debug(acl)
                for  r in base['aauth'][acl]:
                    rule = r['rule']
                    if '_mac_' in rule and '_name_' in rule:
                        logger.debug('mac and name exist')
                        if mac == rule['_mac_'] and (username == rule['_name_'] or username == '(null)'):
                            logger.debug('removing based on name and mac')
                            remove.append(acl)
                            break
                    elif '_mac_' in rule and mac == rule['_mac_']:
                        logger.debug('removing based on mac')
                        remove.append(acl)
                        break
                    elif '_name_' in rule and username == rule['_name_']:
                        logger.warning('removing based on name')
                        remove.append(acl)
                        break
        logger.info('remove from auth')
        logger.info(remove)
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

        logger.info('updated base')
        logger.info(base)
        return base, removed

    def deauthenticate(self, username, mac, logger=None):
        """Deauthenticates a username or MAC address.
        Args:
            username (str): may be None or '(null)' which is treated as None.
            mac (str): MAC address
        Returns:
            True if a client that is authed has rules removed, or if client is not authed. other wise false (faucet fails to reload)
        """
        if self.is_authenticated(mac, username):
            logger.info('user: {} mac: {} already authenticated removing'.format(username, mac))
            self.remove_from_authed_dict(username, mac, logger)
            # update base
            base, changed = self.remove_from_base(username, mac, logger=logger)
            # update faucet only if config has changed
            if changed:
                logger.info('base has changed. removing from faucet')
                final = create_faucet_acls(base, logger=logger)
                write_yaml(final, self.faucet_acl_filename + '.tmp', True)

                self.backup_file(self.faucet_acl_filename)
                self.swap_temp_file(self.faucet_acl_filename)
                # sighup.
                start_count = self.get_faucet_reload_count()
                self.send_signal(signal.SIGHUP)
                logger.info('deauth signal sent')
                for i in range(400):
                    end_count = self.get_faucet_reload_count()
                    if end_count > start_count:
                        logger.info('deauth - faucet has reloaded.')
                        return True
                    time.sleep(0.05)
                    logger.info('deauth - waiting for faucet to process sighup config reload on. %d' % i)
                logger.error('deauth - faucet did not process sighup within 400 * 0.05 seconds.')
                return False
        return True

    def backup_file(self, filename):
        """Backup a file. appends '.bak#' to filename.
        Args:
            filename (str)
        """
        directory = os.path.dirname(filename)
        if directory == '':
            directory = '.'

        filenames = ''.join(os.listdir(directory))
        search_str = os.path.basename(filename) + '.bak'
        
        matches = re.findall(search_str, filenames)

        i = str(len(matches) + 1)

        # backup old current
        shutil.copy2(filename, filename + '.bak' + i)

    def swap_temp_file(self, filename):
        """Renames the temporary file to become the original.
        Args:
            filename (str)
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
            username (str): optional
            mac (str)
            switch (str): optional
            port (str): optional. if switch is used so should port and vice versa.
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
        """Add an authenticted user, ... to the authed_users dictionary
        Args:
            username (str)
            mac (str): MAC address.
            switch (str): the name of the switch username has authenticated on.
            port (str): the port the username has authenticated on.
        """
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

    def remove_from_authed_dict(self, username, mac, logger):
        """Remove the mac from the authed_users dictionary.
        If username is None or '(null)' as is the case with some deauthentications,
        the mac is removed from all users.
        Args:
            username (str): may be None or '(null)'.
            mac (str): MAC address,
        """
        if username and username != '(null)':
            if username in self.authed_users:
                logger.info('removing user %s' % username)
                del self.authed_users[username][mac]
        else:
            remove_users = []
            for user, usermac in list(self.authed_users.items()):
                if mac in usermac:
                    remove_users.append(user)
            for user in remove_users:
                logger.info('removing user %s. wildcard mac' % username)
                del self.authed_users[user][mac]


if __name__ == '__main__':
    main()
