"""Utility Classes and functions for auth_app
"""
# pytype: disable=pyi-error
import re
import requests

class HashableDict(dict):
    '''Used to compared if rules (dictionaries) are the same.
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
    _hex = '%012x' % int(mac_as_float_str.split('.')[0])
    macstr = _hex[:2] + ':' + _hex[2:4] + \
                 ':' + _hex[4:6] + ':' + _hex[6:8] + \
                 ':' + _hex[8:10] + ':' +  _hex[10:12]
    return macstr


def dpid_name_to_map(lines):
    '''Converts a list of lines containing the faucet_config_dp_name,
       (from prometheus client (faucet)) to a dictionary.
    Args:
        lines (list): prometheus lines of 'faucet_config_dp_name'.
    Returns:
        dictionary of dpid to name.
    '''
    dpid_to_name = {}
    for line in lines:
        # TODO maybe dont use regex?
        _, _, dpid, _, name, _ = re.split('[{=",]+', line)
        dpid_to_name[dpid] = name
    return dpid_to_name


def is_rule_in(rule, list_):
    """Searches a list of HashableDicts for an item equal to rule.
    Args:
        rule: an acl dict
        list_:a list of HashableDicts
    Returns:
        True if rule is is equal to item in list_, false otherwise
    """
    hash_rule = HashableDict(rule)
    for item in list_:
        if hash_rule == item:
            return True
    return False


def get_hashable_list(list_):
    """Creates a list of HashableDict for a list of dict.
    Args:
        list_: a list of dicts (standard python version)
    Returns:
        a list of HashableDict
    """
    hash_list = []
    for item in list_:
        hash_list.append(HashableDict(item))
    return hash_list

def scrape_prometheus(prom_url):
    """Query prometheus specified by config. Removes comment lines.
    Returns:
        string containing all prometheus variables without comments.
    """
    prom_vars = []
    for prom_line in requests.get(prom_url).text.split('\n'):
        if not prom_line.startswith('#'):
            prom_vars.append(prom_line)
    return '\n'.join(prom_vars)
