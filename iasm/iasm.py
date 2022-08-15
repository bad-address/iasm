from .arch import get_engines, _supported_regs, select_registers
from .shell import Shell
from .doc import Documentation
from .cmdline import build_argparser

from keystone import KsError
from unicorn import UcError

import sys
import threading


def main():
    parser = build_argparser()
    args = parser.parse_args()

    args.timeout = max(int(args.timeout), 1)

    init_inputs = []
    if args.init_file:
        with open(args.init_file, 'rt') as f:
            init_inputs = list(f.readlines())

    # Initialize engines
    ks, mu, regs, pc, mem = get_engines(args.arch, args.mode)

    # What registers do we want to show by default always
    reg_globs = args.reg_globs
    if not reg_globs:
        reg_globs = _supported_regs[args.arch][-2]

    visible_regs = list(select_registers(regs, reg_globs))

    # Create prompt/shell object.
    doc = None
    sh = Shell(
        args.style, regs, pc, mem, mu, 4, doc, args.simple_prompt,
        args.no_history, visible_regs
    )

    # Show regs and exit if requested
    if args.show_regs:
        sh.display_registers(columns=5)
        sys.exit(0)

    # Load the documentation
    doc = Documentation(args.arch, args.isa_version)
    sh.doc = doc

    # TODO what is the meaning of a loop?
    pc.val = pc_addr = args.pc_addr

    # map code segment
    mem[pc_addr:pc_addr + args.code_sz] = 0
    while True:
        try:
            if init_inputs:
                text = init_inputs.pop(0)
            else:
                sh.display_registers(visible_regs)
                text = sh.prompt()

            code_comment = sh.process_command_or_return_code(text)
            if code_comment is None:
                continue
            code, comment = code_comment

            try:
                ret = []  # ret == [instrs, None] or [None, error]

                def parse_assembly():
                    err = None
                    try:
                        instrs, _ = ks.asm(code, as_bytes=True)
                    except Exception as e:
                        instrs, err = None, e

                    ret.extend((instrs, err))

                th = threading.Thread(target=parse_assembly, daemon=True)
                th.start()
                th.join(args.timeout)

                # keystone hang?
                if not ret or th.is_alive():
                    raise TimeoutError()

                instrs, err = ret

                # keystone failed?
                if err is not None:
                    raise err

                # valid assembly but not instructions there (like a comment)
                if not instrs:
                    continue
            except TimeoutError as e:
                sh.print(
                    "Parse assembly timed out (possible Keystone bug/syntax error). Aborting."
                )
                sys.exit(1)
            except KsError as e:
                sh.print("Syntax error: %s" % e)
                continue

            try:
                # write machine code to be emulated to memory
                mu.mem_write(pc_addr, instrs)
            except UcError as e:
                sh.print("Memory write error: %s" % e)
                continue

            try:
                # emulate code in infinite time & unlimited instructions
                mu.emu_start(
                    pc_addr,
                    pc_addr + len(instrs),
                    timeout=args.timeout * 1000
                )
            except UcError as e:
                sh.print("Execution error: %s" % e)
                continue

            pc_addr += len(instrs)

        except KeyboardInterrupt:
            continue
        except EOFError:
            break
        else:
            pass
