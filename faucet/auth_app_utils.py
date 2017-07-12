"""Utility Classes and functions for auth_app
"""

import re

class HashableDict(dict):
    '''
        Copied from http://stackoverflow.com/a/1151686
    '''
    def __key(self):
        return tuple((k, self[k]) for k in sorted(self))

    def __hash__(self):
        return hash(self.__key())

    def __eq__(self, other):
        return self.__key() == other.__key()


def float_to_mac(mac_as_float_str):
    """Convert a float string to a mac address string
    Args:
        mac_as_float_str (str): float represented as a string e.g. "123456.0"
            This float should be a whole number. (Right of the decimal == 0)
    Returns:
        MAC Address as a string. e.g. "00:00:00:01:e2:40"
    """
    h = '%012x' % int(mac_as_float_str.split('.')[0])
    macstr = h[:2] + ':' + h[2:4] + \
                 ':' + h[4:6] + ':' + h[6:8] + \
                 ':' + h[8:10] + ':' +  h[10:12]
    return macstr


def dpid_name_to_map(lines):
    '''Converts a list of lines containing the faucet_config_dp_name,
       (from prometheus client (faucet)) to a dictionary.
    :param lines list
    :returns dictionary
    '''
    dpid_to_name = {}
    for line in lines:
        # TODO maybe dont use regex?
        _, _, dpid, _, name, _ = re.split('[{=",]+', line)
        dpid_to_name[dpid] = name
    return dpid_to_name


def dp_port_mode_to_map(lines):
    '''Converts a list of lines containing dp_port_mode,
       (from prometheus client (faucet)) to a dictionary dictionary.
    :param lines list
    :returns dictionary
    '''
    dpid_port_mode = {}
    for line in lines:
        _, _, dpid, _, port, mode_int, _ = re.split(r'\W+', line)
        if int(mode_int) == 1:
            mode = 'access'
        else:
            mode = None
        if dpid not in dpid_port_mode:
            dpid_port_mode[dpid] = {}

        dpid_port_mode[dpid][port] = mode
    return dpid_port_mode


def is_rule_in(rule, list_):
    """Searches a list of HashableDicts for an item equal to rule.
    :param rule an acl dict
    :param list_ a list of HashableDicts
    :return True if rule is is equal to item in list_, false otherwise
    """
    hash_rule = HashableDict(rule)
    for item in list_:
        if hash_rule == item:
            return True
    return False


def get_hashable_list(list_):
    """Creates a list of HashableDict for a list of dict.
    :param list_ a list of dicts (standard python version)
    :return a list of HashableDict
    """
    hash_list = []
    for item in list_:
        hash_list.append(HashableDict(item))
    return hash_list

