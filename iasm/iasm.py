from .arch import get_engines, _supported_regs, select_registers
from .shell import create_shell_session, display_registers, process_command_or_return_code
from .cmdline import build_argparser

from keystone import KsError


def main():
    parser = build_argparser()
    args = parser.parse_args()

    # Initialize engines
    ks, mu, regs, pc, mem = get_engines(args.arch, args.mode)

    reg_globs = args.reg_globs
    if not reg_globs:
        reg_globs = _supported_regs[args.arch][-1]

    visible_regs = list(select_registers(regs, reg_globs))

    # Create prompt object.
    session = create_shell_session(args.style)

    # memory address where emulation starts
    ADDRESS = 0x1000000

    # map 2MB memory for this emulation
    mem[ADDRESS:ADDRESS + args.code_sz] = 0

    # map 0x2000 bytes (8KB) memory to play with
    mem[0x2000:0x4000] = 0

    # TODO what is the meaning of a loop?
    pc.val = ADDRESS
    pc_addr = ADDRESS
    while True:
        try:
            display_registers(visible_regs, columns=4)

            text = session.prompt('%s> ' % pc.repr_val())
            code_comment = process_command_or_return_code(text, regs, mem, mu)
            if code_comment is None:
                continue
            code, comment = code_comment

            try:
                instrs, _ = ks.asm(code, as_bytes=True)
                if not instrs:
                    continue
            except KsError as e:
                print("Syntax error: %s" % e)
                continue

            # write machine code to be emulated to memory
            mu.mem_write(pc_addr, instrs)

            # emulate code in infinite time & unlimited instructions
            mu.emu_start(pc_addr, pc_addr + len(instrs))
            pc_addr += len(instrs)

        except KeyboardInterrupt:
            continue
        except EOFError:
            break
        else:
            pass
