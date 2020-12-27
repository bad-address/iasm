from prompt_toolkit import PromptSession

from pygments.lexers.asm import NasmLexer
from pygments.lexers.python import Python3Lexer
from prompt_toolkit.lexers import PygmentsLexer

from pygments.lexer import DelegatingLexer, do_insertions
from pygments.token import Comment

from .mem import Bytearray

COMMENT_SYM = ";"
PY_EXEC_SYM = ";!"


# Hacked version of DelegatingLexer that switch from one Lexer (NasmLexer)
# to another (Python3Lexer) when a Comment is found at the begin of
# the line (i==0) and starts with PY_EXEC_SYM.
class NasmPythonLexer(DelegatingLexer):
    def __init__(self, **options):
        super().__init__(Python3Lexer, NasmLexer, **options)

    def get_tokens_unprocessed(self, text):
        buffered = ''
        insertions = []
        lng_buffer = []
        for i, t, v in self.language_lexer.get_tokens_unprocessed(text):
            if t is Comment.Single and v.startswith(PY_EXEC_SYM) and i == 0:
                if lng_buffer:
                    insertions.append((len(buffered), lng_buffer))
                    lng_buffer = []
                buffered += v
            else:
                lng_buffer.append((i, t, v))
        if lng_buffer:
            insertions.append((len(buffered), lng_buffer))
        return do_insertions(
            insertions, self.root_lexer.get_tokens_unprocessed(buffered)
        )


from pygments.styles import get_style_by_name
from prompt_toolkit.styles.pygments import style_from_pygments_cls

from tabulate import tabulate
import copy


def py_shell(cmd, regs, mem, mu):
    current_ctx = {r.name: r.val for r in regs}
    current_ctx['U'] = mu
    current_ctx['M'] = mem

    new_ctx = copy.copy(current_ctx)  # shallow copy
    try:
        try:
            # let's see if we can eval it as an expression
            ret = eval(cmd, None, new_ctx)
        except SyntaxError:
            # probably it is not an expression, let's try
            # now as a full statement
            exec(cmd, None, new_ctx)
            for reg in regs:
                if new_ctx[reg.name] != current_ctx[reg.name]:
                    reg.val = new_ctx[reg.name]
        else:
            if isinstance(ret, Bytearray):
                ret = repr(ret)
            if ret is not None:
                print(ret)
    except Exception as err:
        print("Eval error:", err)


def create_shell_session(style):
    style = style_from_pygments_cls(get_style_by_name(style))

    session = PromptSession(
        lexer=PygmentsLexer(NasmPythonLexer),
        style=style,
        include_default_pygments_style=False
    )

    return session


def display_registers(regs, columns):
    n = 4
    tmp = [(r.display_name(), r.repr_val()) for r in regs]
    tmp = [sum(tmp[i:i + n], ()) for i in range(0, len(tmp), n)]

    print(tabulate(tmp, colalign=("right", "left"), disable_numparse=True))


def process_command_or_return_code(cmd, regs, mem, mu):
    if cmd.startswith(PY_EXEC_SYM):
        cmd = cmd[len(PY_EXEC_SYM):].strip()
        py_shell(cmd, regs, mem, mu)
        return None

    if COMMENT_SYM in cmd:
        return cmd.split(COMMENT_SYM, 1)
    else:
        return cmd, ''
