import hashlib
import logging
import os

import ruamel.yaml
from ruamel.yaml.comments import CommentedMap
from ruamel.yaml.util import load_yaml_guess_indent

import config_parser_util
import auth_yaml

def read_config(config_file, logname, guess_indent=False):
    logger = get_logger(logname)
    try:
        with open(config_file, 'r') as stream:
            if guess_indent:
                conf, ind, bsi = auth_yaml.locus_load_yaml_guess_indent(stream, config_file)
                return conf, ind, bsi
            else:
                return auth_yaml.locus_round_trip_load(stream, conf_file=config_file)
    except ruamel.yaml.YAMLError as ex:
        logger.error('Error in file %s (%s)', config_file, str(ex))
        return None
#    return conf, ind, bsi

def write_config_file(top_level, data):
    """Overwrites the specified (in data) configurations.
    :param top_level the name of the top level dict e.g. 'acls', 'dps', ...
    :param data list of LocusCommentedMap object to overwrite part of the current config.
        The top map object specifies the config_file.
    """

    # TODO this assumes that the top level structure wont be changed and only a sub structure.
    # might want to add so all acls can be written, etc. and that the 2nd level structures do not
    # share the same name with another 2nd level, even if different parent.


    # 'i' will be a LocusCommentMap with the acl or dp. i.conf_file is the file for all its children. 
    # for each second level structure
    for i in data:
        conf, ind, bsi = read_config(i.conf_file, "writelog", guess_indent=True)
        for header, config in i.items():
            conf[top_level][header] = config
        # dump yaml
        ruamel.yaml.round_trip_dump(conf, open(i.conf_file, 'w'), indent=ind, block_seq_indent=bsi)
    return


def get_logger(logname):
    return logging.getLogger(logname + '.config')

def dp_include(config_hashes, config_file, logname, top_confs):
    """Pretty much copied from faucet/config_parser.py
    Changed 1 line so uses different read_config, which also returns the indent and block sequence indent.
    TODO make this change in original, and remove this if tests all good.
    """
    logger = get_logger(logname)
    if not os.path.isfile(config_file):
        logger.warning('not a regular file or does not exist: %s', config_file)
        return False
    conf = read_config(config_file, logname, guess_indent=False)

    if not conf:
        logger.warning('error loading config from file: %s', config_file)
        return False

    # Add the SHA256 hash for this configuration file, so FAUCET can determine
    # whether or not this configuration file should be reloaded upon receiving
    # a HUP signal.
    new_config_hashes = config_hashes.copy()
    new_config_hashes[config_file] = config_parser_util.config_file_hash(config_file)

    # Save the updated configuration state in separate dicts,
    # so if an error is found, the changes can simply be thrown away.
    new_top_confs = {}
    for conf_name, curr_conf in top_confs.items():
        new_top_confs[conf_name] = curr_conf.copy()
        new_top_confs[conf_name].update(conf.pop(conf_name, {}))

    for include_directive, file_required in (
            ('include', True),
            ('include-optional', False)):
        for include_file in conf.pop(include_directive, []):
            include_path = config_parser_util.dp_config_path(include_file, parent_file=config_file)
            if include_path in config_hashes:
                logger.error(
                    'include file %s already loaded, include loop found in file: %s',
                    include_path, config_file,)
                return False
            if not dp_include(
                    new_config_hashes, include_path, logname, new_top_confs):
                if file_required:
                    logger.error('unable to load required include file: %s', include_path)
                    return False
                else:
                    new_config_hashes[include_path] = None
                    logger.warning('skipping optional include file: %s', include_path)
                    
    # Actually update the configuration data structures,
    # now that this file has been successfully loaded.
    config_hashes.update(new_config_hashes)
    for conf_name, new_conf in new_top_confs.items():
        top_confs[conf_name].update(new_conf)
    return True


def load_acl(config_path, switchname, switchport):
    """Loads the acl as specified by the acl_in field on switchname switchport.
    Both of switchname and switch must be specified.
    :param config_path path to yaml configuration file to load.
    :param switchname name of switch/datapath.
    :param switchport the port of switchname.
    :return tuple of dp name and dict-like config object.
    """
 
    top_conf = load_top_conf(config_path)
    
    acls = top_conf["acls"]
    dps = top_conf["dps"]

    acl_in = dps[switchname]["interfaces"][switchport]["acl_in"]

    acl_map = acls[acl_in]
    if acl_map is not None:
        print("acl_in {}, acl_map {}".format(acl_in, acl_map))
        return acl_in, acl_map

    raise NotInYAMLError("Cannot find acl with dp named: {}, and port: {} in config file {}".format(switchname, switchport, config_path))


def load_acls(config_path):
    """Loads all acls across all files in config_path (include/include-optional)
    :param config_path path to yaml configuration file to load.
    :return dict of <name, LocusCommentedMap>
    """
    return load_top_conf(config_path)["acls"]
    

def load_dp(config_path, switchname=None, dp_id=None):
    """Loads a single datapath.
    One of switchname or dp_id must be specified.
    :param config_path path to yaml configuration file to load.
    :param switchname name of switch/datapath to search for.
    :param dp_id id of switch/datapath to search for.
    :return tuple of dp name and dict-like config object.
    """
    dps = load_dps(config_path)
    if switchname is not None:
        return switchname, dps[switchname]

    for name, com_map in dps.items():
        if dp_id is not None and com_map["dp_id"] == dp_id:
            return name, com_map

    raise NotInYAMLError("Cannot find dp named: {}, or dp id: {} in config file {}".format(switchname, dp_id, config_path))


def load_dps(config_path):
    """Loads all datapaths across all files in config_path (include/include-optional)
    :param config_path path to yaml configuration file to load.
    :return dict of <name, LocusCommentedMap> e.g. s1 : LCM (dpid:10000, ...)
    """
    top = load_top_conf(config_path)
    return top["dps"]


def load_top_conf(config_path):
    """Loads the top level configuraions.
    :param config_path path to yaml configuration file.
    :return dict of 4 main top level config LocusCommentedMap
    """
    config_hashes = {} 
    top_confs = {
            "acls": {},
            "dps": {},
            "routers": {},
            "vlans": {}
            }
    dp_include(config_hashes, config_path, "loadtop", top_confs)

    return top_confs


class NotInYAMLError(LookupError):
    """Exception for if object cannot be found in the loaded yaml file object.
    """
    pass
