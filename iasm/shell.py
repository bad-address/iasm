from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory

from pygments.lexers.asm import NasmLexer
from pygments.lexers import MarkdownLexer
from pygments.lexers.python import Python3Lexer
from prompt_toolkit.lexers import PygmentsLexer

from pygments.formatters.terminal import TerminalFormatter

from pygments.lexer import DelegatingLexer, do_insertions
from pygments.token import Comment

import pygments

from .mem import Bytearray
from .arch import FlagRegister

from pydoc import pipepager

import os.path

COMMENT_SYM = ";"
PY_EXEC_SYM = ";!"
DOC_SYM = " ?"

HISTORY_FILEPATH = "~/.iasm_history"


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


class Shell:
    def __init__(self, style, regs, pc, mem, mu, columns, doc):
        self.session = self._create_shell_session(style)

        self.regs = regs
        self.pc = pc
        self.mem = mem
        self.mu = mu
        self.columns = columns

        self.doc = doc

    def prompt(self):
        return self.session.prompt('%s> ' % self.pc.repr_val())

    def exec_python(self, cmd):
        regs = self.regs
        mem = self.mem
        mu = self.mu

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

    def _create_shell_session(self, style):
        self.style = style = style_from_pygments_cls(get_style_by_name(style))

        history_path = os.path.expanduser(HISTORY_FILEPATH)
        history = FileHistory(history_path)

        kb = KeyBindings()

        #   >         X    X    (white line)
        #    ^^^^^^^  ^    ^
        #  indent     |    |
        #           enter enter
        #             \    \
        #             finish (single line)

        #   > mov r0X, r1X
        #    ^      ^    ^
        # no indent |    |
        #         enter enter
        #           \    \
        #           finish (single line)

        #   >   mov r0X, r1X
        #    ^^^      ^    ^
        #  indent     |    |
        #           enter enter
        #             |    \
        #           insert  insert
        #             continue (new block/multiline)

        #   >   mov r0X, r1
        #   :   mov r2^, r3X
        #    ^^^      |    ^
        #  indent     |    |
        #           enter enter
        #             |    \
        #           insert  insert
        #             continue (already block/multiline)

        #   >   mov r0X, r1
        #   :         ^    X    (white line)
        #    ^^^^^^^  |    ^
        #  indent     |    |
        #           enter enter --> finish
        #             |
        #           insert
        #             continue (already block/multiline)

        #   >   mov r0X, r1
        #   : mov r2, ^  r3X
        #    ^        |    ^
        #  no indent  |    |
        #           enter enter --> finish
        #             |
        #           insert
        #             continue (already block/multiline)

        @kb.add('enter')
        def _(event):
            buf = event.current_buffer
            last_line = buf.text.split("\n")[-1]

            is_indented = last_line.startswith(" ")
            is_last_empty = len(last_line.lstrip()) == 0
            is_multiline = '\n' in buf.text
            is_at_end = buf.cursor_position == len(buf.text)

            finish = None
            # unrolled logic:
            #   if is_last_empty and not is_multiline and is_indented:
            #       finish = True
            #
            #   elif is_last_empty and not is_multiline and not is_indented:
            #       finish = True
            #
            #   elif not is_last_empty and not is_multiline and not is_indented:
            #       finish = True
            #
            #   elif not is_last_empty and not is_multiline and is_indented:
            #       finish = False
            #
            #   elif not is_last_empty and is_multiline and is_indented:
            #       finish = False
            #
            #   elif is_last_empty and is_multiline and is_indented:
            #       if is_at_end:
            #           finish = True
            #       else
            #           finish = False
            #
            #   elif not is_last_empty and is_multiline and not is_indented:
            #       if is_at_end:
            #           finish = True
            #       else
            #           finish = False
            #
            #   elif is_last_empty and is_multiline and not is_indented:
            #       if is_at_end:
            #           finish = True
            #       else
            #           finish = False
            #   else:
            #       assert False
            ####

            if is_multiline:
                if not is_last_empty and is_indented:
                    finish = False
                else:
                    finish = is_at_end == True
            else:
                if not is_last_empty and is_indented:
                    finish = False
                else:
                    finish = True

            assert finish in (True, False)
            if finish:
                buf.validate_and_handle()
            else:
                # TODO this should be the line within the cursor,
                # not necessary the last
                indentation = len(last_line) - len(last_line.lstrip())
                buf.insert_text('\n' + ' ' * indentation)

        def prompt_continuation(width, line_number, wrap_count):
            return " " * (width - 3) + "-> "

        session = PromptSession(
            lexer=PygmentsLexer(NasmPythonLexer),
            style=style,
            include_default_pygments_style=False,
            history=history,
            key_bindings=kb,
            multiline=True,
            prompt_continuation=prompt_continuation,
            auto_suggest=AutoSuggestFromHistory()
        )

        return session

    def display_registers(self, regs=None, columns=None):
        if regs is None:
            regs = self.regs
        if columns is None:
            columns = self.columns

        n = columns
        tmp = [
            (r.display_name(), r.repr_val()) for r in regs
            if not isinstance(r, FlagRegister)
        ]
        tmp = [sum(tmp[i:i + n], ()) for i in range(0, len(tmp), n)]

        print(tabulate(tmp, colalign=("right", "left"), disable_numparse=True))

        n = columns = 1
        tmp = [
            (r.display_name(), r.repr_val()) for r in regs
            if isinstance(r, FlagRegister)
        ]
        tmp = [sum(tmp[i:i + n], ()) for i in range(0, len(tmp), n)]

        print(tabulate(tmp, colalign=("right", "left"), disable_numparse=True))

    def show_doc(self, cmd):
        if not self.doc.enabled():
            print("No documentation was loaded")
            return

        name = cmd.strip().split()[0]

        try:
            doc = self.doc.doc_for_instr(name)
        except KeyError:
            print("No documentation was found for '%s'" % name)
            return

        pipepager(doc, 'pypager')
        return

    def process_command_or_return_code(self, cmd):
        if cmd.rstrip().endswith(DOC_SYM):
            self.show_doc(cmd)
            return None

        if cmd.startswith(PY_EXEC_SYM):
            cmd = cmd[len(PY_EXEC_SYM):].strip()
            self.exec_python(cmd)
            return None

        if COMMENT_SYM in cmd:
            return cmd.split(COMMENT_SYM, 1)
        else:
            return cmd, ''
