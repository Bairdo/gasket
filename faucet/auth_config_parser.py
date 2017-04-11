import hashlib
import logging
import os

import ruamel.yaml
from ruamel.yaml.comments import CommentedMap
from ruamel.yaml.util import load_yaml_guess_indent

import config_parser_util
import auth_yaml

def read_config(config_file, logname):
    logger = get_logger(logname)
    try:
        with open(config_file, 'r') as stream: 
            conf, ind, bsi = auth_yaml.locus_load_yaml_guess_indent(stream, config_file)
    except ruamel.yaml.YAMLError as ex:
        logger.error('Error in file %s (%s)', config_file, str(ex))
        return None
    return conf, ind, bsi

def write_config_file(header, data):

    # TODO this assumes that the top level structure wont be changed and only a sub structure.
    # might want to add so all acls can be written, etc.

    # read conf_file into c
    conf, ind, bsi = read_config(data[0].conf_file, "writelog")
    # replace c[header] with data   
    for name, c in conf.items():
        if isinstance(c, auth_yaml.LocusCommentedMap):
            if header in c.keys():
                conf[name][header] = data
                break
    # dump yaml
    ruamel.yaml.round_trip_dump(conf, open(data[0].conf_file, 'w'), indent=ind, block_seq_indent=bsi)

    return


def get_logger(logname):
    return logging.getLogger(logname + '.config')

def dp_include(config_hashes, config_file, logname, top_confs):
    logger = get_logger(logname)
    if not os.path.isfile(config_file):
        logger.warning('not a regular file or does not exist: %s', config_file)
        return False
    conf, ind, bsi = read_config(config_file, logname)

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
    top_conf = load_top_conf(config_path)
    
    acls = top_conf["acls"]
    dps = top_conf["dps"]

    acl_in = ""

    for name, dp_map in dps.items():

        if switchname == name:
            acl_in = dp_map["interfaces"][switchport]["acl_in"]
            break

    for name, acl_map in acls.items():
        if name == acl_in:
            return name, acl_map
    raise NotInYAMLError("Cannot find acl with dp named: {}, and port: {} in config file {}".format(switchname, switchport, config_path))


def load_acls(config_path):
    return load_top_conf(config_path)["acls"]
    

def load_dp(config_path, switchname=None, dp_id=None):

    dps = load_dps(config_path)

    for name, com_map in dps.items():
        if switchname is not None and switchname == name:
            return name, com_map
        if dp_id is not None and com_map["dp_id"] == dp_id:
            return name, com_map

    raise NotInYAMLError("Cannot find dp named: {}, or dp id: {} in config file {}".format(switchname, dp_id, config_path))


def load_dps(config_path):
    top = load_top_conf(config_path)
    return top["dps"]


def load_top_conf(config_path):

    config_hashes = {} 
    top_confs = {
            "acls": {},
            "dps": {},
            "routers": {},
            "vlans": {}
            }
    dp_include(config_hashes, config_path, "blah", top_confs)

    return top_confs


class NotInYAMLError(LookupError):
    pass
