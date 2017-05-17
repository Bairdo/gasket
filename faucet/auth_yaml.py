'''This file contains various overrides of ruamel.yaml to essentially mark which file
    a structure (ruamel.yaml.CommentedMap) came from.i
   The code is pretty much copied from the ruamel.yaml source, with 1-2 lines changed per function.
   This is then used at write time to write the structure back to the file it came from.
   auth_config_parser.py conatins a copy of faucet/config_parser.py#dp_include() which uses the 
    ruamel.yaml library instead of pyyaml.
'''

from ruamel.yaml.reader import Reader
from ruamel.yaml.scanner import Scanner, RoundTripScanner
from ruamel.yaml.parser import Parser, RoundTripParser
from ruamel.yaml.composer import Composer
from ruamel.yaml.resolver import VersionedResolver
from ruamel.yaml.constructor import RoundTripConstructor
from ruamel.yaml.comments import CommentedMap
from ruamel.yaml.representer import RoundTripRepresenter
from ruamel.yaml.compat import text_type, binary_type

class LocusRoundTripConstructor(RoundTripConstructor):
    """stores the config file with each CommentedMap.
    """
    def __init__(self, preserve_quotes, loader, conf_file, *args, **kwargs):
        super().__init__(preserve_quotes=preserve_quotes, loader=loader)
        self.conf_file = conf_file

    def construct_yaml_map(self, node):
        # type: (Any) -> Any
        data = LocusCommentedMap(self.conf_file)
        data._yaml_set_line_col(node.start_mark.line, node.start_mark.column)
        if node.flow_style is True:
            data.fa.set_flow_style()
        elif node.flow_style is False:
            data.fa.set_block_style()
        yield data
        self.construct_mapping(node, data)

    def construct_undefined(self, node):
        # type: (Any) -> Any
        try:
            data = LocusCommentedMap(self.conf_file)
            data._yaml_set_line_col(node.start_mark.line, node.start_mark.column)
            if node.flow_style is True:
                data.fa.set_flow_style()
            elif node.flow_style is False:
                data.fa.set_block_style()
            data.yaml_set_tag(node.tag)
            yield data
            self.construct_mapping(node, data)
        except:
            raise ConstructorError(
                None, None,
                "could not determine a constructor for the tag %r" %
                utf8(node.tag),
                node.start_mark)


class LocusRoundTripLoader(Reader, RoundTripScanner, RoundTripParser, Composer,
                              LocusRoundTripConstructor, VersionedResolver):
    def __init__(self, stream, version=None, preserve_quotes=None, conf_file=None):
        # type: (StreamTextType, VersionType, bool) -> None
        # self.reader = Reader.__init__(self, stream)
        Reader.__init__(self, stream, loader=self)
        RoundTripScanner.__init__(self, loader=self)
        RoundTripParser.__init__(self, loader=self)
        Composer.__init__(self, loader=self)
        LocusRoundTripConstructor.__init__(self, preserve_quotes=preserve_quotes, loader=self, conf_file=conf_file)
        VersionedResolver.__init__(self, version, loader=self)
      

class LocusCommentedMap(CommentedMap):

    def __init__(self, conf_file, *args, **kwargs):
        super().__init__()

        self.conf_file = conf_file


def load(stream, version=None, preserve_quotes=None, conf_file=None):
    # type: (StreamTextType, Any, VersionType, Any) -> Any
    """
    Parse the first YAML document in a stream
    and produce the corresponding Python object.
    """
    loader = LocusRoundTripLoader(stream, version, preserve_quotes=preserve_quotes, conf_file=conf_file)
    try:
        return loader._constructor.get_single_data()
    finally:
        loader._parser.dispose()


def locus_round_trip_load(stream, version=None, preserve_quotes=None, conf_file=None):
    # type: (StreamTextType, VersionType, bool) -> Any
    """
    Parse the first YAML document in a stream
    and produce the corresponding Python object.
    Resolve only basic YAML tags.
    """
    return load(stream, version, preserve_quotes=preserve_quotes, conf_file=conf_file)
    

def locus_load_yaml_guess_indent(stream, config_file, **kw):
    # type: (StreamTextType, Any) -> Any
    """guess the indent and block sequence indent of yaml stream/string

    returns round_trip_loaded stream, indent level, block sequence indent
    - block sequence indent is the number of spaces before a dash relative to previous indent
    - if there are no block sequences, indent is taken from nested mappings, block sequence
    indent is unset (None) in that case
    """

    # load a yaml file guess the indentation, if you use TABs ...
    def leading_spaces(l):
        # type: (Any) -> int
        idx = 0
        while idx < len(l) and l[idx] == ' ':
            idx += 1
        return idx

    if isinstance(stream, text_type):
        yaml_str = stream
    elif isinstance(stream, binary_type):
        yaml_str = stream.decode('utf-8')  # most likely, but the Reader checks BOM for this
    else:
        yaml_str = stream.read()
    map_indent = None
    indent = None  # default if not found for some reason
    block_seq_indent = None
    prev_line_key_only = None
    key_indent = 0
    for line in yaml_str.splitlines():
        rline = line.rstrip()
        lline = rline.lstrip()
        if lline.startswith('- '):
            l_s = leading_spaces(line)
            block_seq_indent = l_s - key_indent
            idx = l_s + 1
            while line[idx] == ' ':  # this will end as we rstripped
                idx += 1
            if line[idx] == '#':     # comment after -
                continue
            indent = idx - key_indent
            break
        if map_indent is None and prev_line_key_only is not None and rline:
            idx = 0
            while line[idx] in ' -':
                idx += 1
            if idx > prev_line_key_only:
                map_indent = idx - prev_line_key_only
        if rline.endswith(':'):
            key_indent = leading_spaces(line)
            idx = 0
            while line[idx] == ' ':  # this will end on ':'
                idx += 1
            prev_line_key_only = idx
            continue
        prev_line_key_only = None
    if indent is None and map_indent is not None:
        indent = map_indent
    return locus_round_trip_load(yaml_str, conf_file=config_file, **kw), indent, block_seq_indent


LocusRoundTripConstructor.add_constructor(
    u'tag:yaml.org,2002:map',
    LocusRoundTripConstructor.construct_yaml_map)

# allows our LocusCommentedMap to be written back as a dict.
RoundTripRepresenter.add_representer(LocusCommentedMap,
                                             RoundTripRepresenter.represent_dict)
