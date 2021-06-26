from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit import print_formatted_text, HTML
from prompt_toolkit.styles.pygments import style_from_pygments_cls

from prompt_toolkit.lexers import PygmentsLexer

from pygments.lexers.asm import NasmLexer
from pygments.lexers.python import Python3Lexer

from pygments.lexer import DelegatingLexer, do_insertions
from pygments.token import Comment

from pygments.styles import get_style_by_name

from tabulate import tabulate, TableFormat, Line, DataRow

from .mem import ImmutableBytes
from .arch import FlagRegister, select_registers

from pydoc import pipepager
from appdirs import AppDirs

import os.path
import os
import copy

from functools import partial

COMMENT_SYM = ";"
PY_EXEC_SYM = ";!"
DOC_SYM = " ?"

HISTORY_FILEPATH = "history"


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


def _styled_datarow(begin, sep, end, cls, cell_values, colwidths, colaligns):
    ''' Function that add a HTML style <cls> to each even cell value.
        The rest of the parameters follows the tabulate's definition.
        '''
    values = (
        c if i % 2 else ('<%s>%s</%s>' % (cls, c, cls))
        for i, c in enumerate(cell_values)
    )
    return (begin + sep.join(values) + end).rstrip()


# Table format for the registers based on tabulate's 'simple' format
_registers_table_fmt = TableFormat(
    lineabove=Line("", "-", "  ", ""),
    linebelowheader=Line("", "-", "  ", ""),
    linebetweenrows=None,
    linebelow=Line("", "-", "  ", ""),
    headerrow=DataRow("", "  ", ""),
    datarow=partial(_styled_datarow, "", "  ", "", "pygments.name"),
    padding=0,
    with_header_hide=["lineabove", "linebelow"],
)


class Shell:
    def __init__(
        self, style, regs, pc, mem, mu, columns, doc, simple_prompt,
        no_history, visible_regs
    ):
        self.dirs = AppDirs("iasm", "badaddr")
        self.session = self._create_shell_session(style, no_history)

        self.regs = regs
        self.pc = pc
        self.mem = mem
        self.mu = mu
        self.columns = columns

        self.visible_regs = visible_regs
        self.visible_regs_default = list(visible_regs)  # a copy is required

        self.doc = doc
        self._ps = ':> ' if simple_prompt else '{pc}> '
        self._ps2 = '-> '

        # Variable to avoid displaying the registers more than once
        # This could happen if the user calls show() (see exec_python)
        # The variable is set on display_registers() and reset on prompt()
        self._regs_displayed = False

    def prompt(self):
        ps = self._ps.format(pc=self.pc.repr_val())
        self._regs_displayed = False
        return self.session.prompt(ps)

    def print(self, text):
        print_formatted_text(text, style=self.style)

    def exec_python(self, cmd):
        regs = self.regs
        mem = self.mem
        mu = self.mu

        def show(*reg_globs, stick=False):
            ''' Show the given registers (glob patterns).

                If stick is True, the selected registers will be displayed
                by default before each prompt of the shell.

                If no glob pattern is provided, it will show the registers
                selected from the command line or the default
                of the architecture.

                Call show('') to match no register (useless) and
                show('', stick=True) to disable the display (more useful)
            '''
            if reg_globs:
                sel = list(select_registers(self.regs, reg_globs))
            else:
                sel = self.visible_regs_default

            self.display_registers(sel)
            if stick:
                # update implace
                self.visible_regs[:] = sel

        current_ctx = {r.name: r.val for r in regs}
        current_ctx['U'] = mu
        current_ctx['M'] = mem
        current_ctx['show'] = show

        new_ctx = copy.copy(current_ctx)  # shallow copy
        try:
            try:
                # let's see if we can eval it as an expression
                ret = eval(cmd, None, new_ctx)
            except SyntaxError:
                # probably it is not an expression, let's try
                # now as a full statement
                try:
                    exec(cmd, None, new_ctx)
                except Exception as err:
                    self.print("Exec error: %s" % err)
                else:
                    for reg in regs:
                        if new_ctx[reg.name] != current_ctx[reg.name]:
                            reg.val = new_ctx[reg.name]
            else:
                if isinstance(ret, ImmutableBytes):
                    ret = repr(ret)
                if ret is not None:
                    self.print(ret)
        except Exception as err:
            print("Eval error: %s" % err)

    def _create_shell_session(self, style, no_history):
        user_dir = self.dirs.user_data_dir
        os.makedirs(user_dir, exist_ok=True)

        kb = KeyBindings()
        _add_multiline_keybinding(kb)

        def _prompt_continuation(width, line_number, wrap_count):
            return " " * (width - len(self._ps2)) + self._ps2

        kargs = dict(
            key_bindings=kb,
            multiline=True,
            prompt_continuation=_prompt_continuation,
            enable_suspend=True
        )

        if not no_history:
            history_path = os.path.join(user_dir, HISTORY_FILEPATH)
            history = FileHistory(history_path)
            kargs.update(
                dict(history=history, auto_suggest=AutoSuggestFromHistory())
            )

        self.style = None
        if style != 'none':
            self.style = style_from_pygments_cls(get_style_by_name(style))
            kargs.update(
                dict(
                    lexer=PygmentsLexer(NasmPythonLexer),
                    style=self.style,
                    include_default_pygments_style=False
                )
            )

        session = PromptSession(**kargs)

        return session

    def display_registers(self, regs=None, columns=None):
        if self._regs_displayed:
            return
        self._regs_displayed = True

        if regs is None:
            regs = self.regs
        if columns is None:
            columns = self.columns

        self._display_registers(regs, columns, flag_mode=False)
        self._display_registers(regs, 1, flag_mode=True)

    def _display_registers(self, regs, columns, flag_mode):
        ''' Tabulate and display the registers that are *not* flags
            (if flag_mode is False) or they *are* flags (if flag_mode is True).

            Tabulate with the given columns and the defined self.style.
            '''
        n = columns
        tmp = [
            (r.display_name(), r.repr_val()) for r in regs
            if (not isinstance(r, FlagRegister)) ^ flag_mode
        ]
        tmp = [sum(tmp[i:i + n], ()) for i in range(0, len(tmp), n)]

        # due a bug in tabulate, we cannot use a custom tablefmt
        # if the cells are multiline like in this case.
        tablefmt = 'simple' if flag_mode else _registers_table_fmt

        self._tabulate_and_print(tmp, tablefmt)

    def _tabulate_and_print(self, data, tablefmt):
        ''' Tabulate the given data (list of lists) so each
            even column is aligned to the right and each odd
            column is aligned to the left.

            The given tablefmt allows to use a custom format.

            The result of the tabulation is interpreted as HTML and
            printed using self.style.
            '''
        if not data:
            return
        self.print(
            HTML(
                tabulate(
                    data,
                    colalign=("right", "left"),
                    disable_numparse=True,
                    tablefmt=tablefmt
                )
            ),
        )

    def show_doc(self, cmd):
        if not self.doc.enabled():
            self.print("No documentation was loaded")
            return

        name = cmd.strip().split()[0]

        try:
            doc = self.doc.doc_for_instr(name)
        except KeyError:
            self.print("No documentation was found for '%s'" % name)
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


def _add_multiline_keybinding(kb):
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
