from pygments.lexers.asm import NasmLexer
from pygments.formatters.terminal import TerminalFormatter
from pygments.lexer import RegexLexer, bygroups
from pygments.token import Generic, Text, Keyword, Token

import pygments

from textwrap import TextWrapper
import json
import os

DS_DIR = os.path.join(os.path.dirname(__file__), 'datasheets')

_supported_docs = {
    'arm': {
        'v8': os.path.join(DS_DIR, "armv8.json"),
        'latest': os.path.join(DS_DIR, "armv8.json")
    },
    'arm64': {
        'v8': os.path.join(DS_DIR, "armv8.json"),
        'latest': os.path.join(DS_DIR, "armv8.json")
    },
    'mips': None,
    'sparc': None,
    'x86': None
}


def _wrap(twrapper, multiline):
    tmp = []
    for line in multiline.splitlines(True):
        tmp.extend(twrapper.wrap(line))
    return '\n'.join(tmp)


class TextLexer(RegexLexer):
    name = 'text'
    aliases = ['text']
    filenames = ['*.text']

    tokens = {
        'root': [
            (r'^# .*\n', Generic.Heading),
            (
                r'([^A-Z]*)([A-Z]{3,})(:|\.|\s|$)',
                bygroups(Text, Token.Name.Function, Text)
            ),
            (r'[^A-Z]+', Text),
            (r'[A-Z]{1,2}', Text),
            (r'.', Text),
        ]
    }


def load_datasheet(fname):
    with open(fname, 'rt') as src:
        data = json.load(src)

    asm_lexer = NasmLexer()
    text_lexer = TextLexer()
    formatter = TerminalFormatter()
    twrapper = TextWrapper(
        tabsize=4, initial_indent='  ', subsequent_indent='  '
    )

    docs_by_name = {}
    for section, title, name, descr, syntax in data:
        if section:
            header = "# %s - %s" % (section, title)
        else:
            header = "# %s" % title

        header = pygments.highlight(header, text_lexer, formatter)

        descr = _wrap(twrapper, descr)
        descr = pygments.highlight(descr, text_lexer, formatter)

        if syntax:
            syntax = _wrap(twrapper, syntax)
            syntax = pygments.highlight(syntax, asm_lexer, formatter)

            msg = '%s\n%s\n%s' % (header, descr, syntax)
        else:
            msg = '%s\n%s' % (header, descr)

        if name in docs_by_name:
            docs_by_name[name] += '\n\n' + msg
        else:
            docs_by_name[name] = msg

    assert docs_by_name['reference']
    return docs_by_name


class Documentation:
    def __init__(self, arch, isa_version):
        tmp = _supported_docs[arch]
        if tmp is None:
            self.docs_by_name = None
            self.loaded = True

        else:
            fname = tmp[isa_version]
            self.docs_by_name = fname  # lazy evaluated
            self.loaded = False

    def enabled(self):
        return self.docs_by_name is not None

    def doc_for_instr(self, name):
        if isinstance(self.docs_by_name, dict):
            return self.docs_by_name[name] + '\n\n' + self.reference

        self.docs_by_name = load_datasheet(self.docs_by_name)
        self.reference = self.docs_by_name['reference']
        return self.doc_for_instr(name)
