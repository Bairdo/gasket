import os
import re
import shutil
import signal
import sys
import yaml

from rule_generator import RuleGenerator

def main1():
    with open('acls.yaml') as f:
        doc = yaml.safe_load(f)

    r1 = {}
    r1['rule'] = {}
    r1['rule']['actions'] = {}
    r1['rule']['actions']['allow'] = 1
    r1['rule']['dl_src'] = '66:66:66:66:66:66'
    r1['rule']['user'] = 'mike'
    r2 = {}
    r2['rule'] = {}
    r2['rule']['actions'] = {}
    r2['rule']['actions']['allow'] = 0
    r2['rule']['dl_src'] = '66:66:66:66:66:66'
    r2['rule']['user'] = 'mike'
    
    mike = {}
    mike['port_faucet-1_1'] = [r1, r2]

#    doc['mike'] = mike
#    doc['acls']['port_faucet-1_1'].extend(mike)


    noalias_dumper = yaml.dumper.SafeDumper
    noalias_dumper.ignore_aliases = lambda self, data: True
    
    print(yaml.dump(doc, default_flow_style=False, Dumper=noalias_dumper))

    faucet_yaml = create_faucet_acls(doc, mike)
    print()
    print(yaml.dump(faucet_yaml, default_flow_style=False, Dumper=noalias_dumper))
    doc['mike'] = mike
    doc['acls']['port_faucet-1_1'].extend(mike)
    print('with user')
    print(yaml.dump(doc, default_flow_style=False, Dumper=noalias_dumper))

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

    final = create_faucet_acls(base)
    write_yaml(final, output_f)

def create_faucet_acls(doc, auth_rules=None):
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

    for acl in doc['acls'].items():
        seq = []
        acl_name = acl[0]
        for obj in acl[1]:
            if isinstance(obj, dict) and 'rule' in obj:
                for _, rule in obj.items():
                    new_rule = {}
                    new_rule['rule'] = rule
                    if '_mac_' in rule:
                        del rule['_mac_']
                    if '_name_' in rule:
                        del rule['_name_']
                    seq.append(new_rule)
            if isinstance(obj, list):
                for z in obj:
                    if '_mac_' in z['rule']:
                        del z['rule']['_mac_']
                    seq.append(z)
            if isinstance(obj, str):
                # this is likey just a 'flag' used to mark position to insert the rules when authed
                if obj == 'authed-rules':
                    continue
                else:
                    print('illegal string ' + obj)

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
        logger.warn('opening: ' + filename)
        with open(filename) as f:
            base = yaml.safe_load(f)

        logger.warn('loaded: ' + filename)
        # somehow add the rules to the base where ideally the items in the acl are the pointers.
        # but guess it might not matter, just hurts readability.

        # this is NOT a spelling mistake. this ensures that the auth rules are defined before the use in
        # the port acl. and that the port acl will have the pointer.
        if 'aauth' not in base:
            base['aauth'] = {}
            logger.warn("aauth key did not exist ")
        logger.warn('ready for adding rules')
        logger.warn(rules)
        logger.warn(dir(rules))
        for aclname, acllist in rules.items():
            logger.warn('adding aclist')
            logger.warn('adding aclist named:' + aclname)

            base['aauth'][aclname + user] = acllist
            
            base_acl = base['acls'][aclname]

            i = base_acl.index('authed-rules')
            # insert rules above the authed-rules 'flag'. add 1 for below it.
            base_acl[i:i] = acllist

        # if remove the rule from either the definition or reference, will that remove the other end of the pointer.
        #  because of the way python does the referencing. no it will not.

        # 'rotate' filename - filename.bak, filename.bak.1 this is primiarily for logging, to see how users affect the config.
        logger.warn('write base to tmp')
        # write back to filename 
        write_yaml(base, filename + '.tmp')
        logger.warn('written base to tmp')
        self.backup_file(filename)
        logger.warn('backed up base')
        self.swap_temp_file(filename)
        logger.warn('swapped tmp for base')
        return base

    def authenticate(self, username, mac, switch, port, radius_fields=None, logger=None):
        # get rules to apply
        try:
            rules = self.rule_gen.get_rules(username, 'port_' + switch + '_' + str(port), mac)
            # update base
            logger.warn(username)
            logger.warn(rules)
            base = self.add_to_base_acls(self.base_filename, rules, username, logger=logger)
            logger.warn(base)
            # update faucet
            final = create_faucet_acls(base)
            logger.warn('new Faucet.')
            logger.warn(final)
            write_yaml(final, self.faucet_acl_filename + '.tmp' , True)
            self.backup_file(self.faucet_acl_filename)
            self.swap_temp_file(self.faucet_acl_filename)
            # sighup.
            self.send_signal(signal.SIGHUP)
        except Exception as e:
            logger.critical('except while authenticate')
            logger.exception(e)
    def remove_from_base(self, username, mac):
        with open(self.base_filename) as f:
            base = yaml.safe_load(f)
       
        remove = []

        if 'aauth' in base:
            for acl in base['aauth'].keys():
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

        for acl in base['acls'].keys():
            for rule_name, rules in base['acls'].items():
                for obj in rules:
                    if isinstance(obj, dict):
                        if 'rule' not in obj:
                            continue
                        rule = obj['rule']
                        if '_mac_' in rule and '_name_' in rule:
                            if mac == rule['_mac_'] and (username == rule['_name_'] or username == '(null)'):
                                del obj['rule']
                                removed = True
                        elif '_mac_' in rule and mac == rule['_mac_']:
                            del base['acls'][acl][rule_name]
                            removed = True
                        elif '_name_' in rule and username == rule['_name_']:
                            del base['acls'][acl][rule_name]
                            removed = True

                    if isinstance(obj, list):
                        for rule in obj:
                            rule = rule['rule']
                            if '_mac_' in rule and '_name_' in rule:
                                if mac == rule['_mac_'] and (username == rule['_name_'] or username == '(null)'):
                                    del rule
                                    removed = True
                            elif '_mac_' in rule and mac == rule['_mac_']:
                                del base['acls'][acl][rule_name]
                                removed = True
                            elif '_name_' in rule and username == rule['_name_']:
                                del base['acls'][acl][rule_name]
                                removed = True

            base['acls'][acl] = [value for value in base['acls'][acl] if value != {}]
        

        if removed:
            # only need to write it back if something has actually changed.
            write_yaml(base, self.base_filename + '.tmp')
            self.backup_file(self.base_filename)
            self.swap_temp_file(self.base_filename)

        return base, removed

    def deauthenticate(self, username, mac):
        # update base
        base, changed = self.remove_from_base(username, mac)
        # update faucet only if config has changed
        if changed:
            final = create_faucet_acls(base)
            write_yaml(final, self.faucet_acl_filename + '.tmp', True)

            self.backup_file(self.faucet_acl_filename)
            self.swap_temp_file(self.faucet_acl_filename)
            # sighup.
            self.send_signal(signal.SIGHUP)

    def __init__(self, config):
        self.config = config

        self.rule_gen = RuleGenerator(self.config.rules)
        self.base_filename = self.config.base_filename
        self.faucet_acl_filename = self.config.acl_config_file


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

