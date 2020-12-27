from keystone import *
from unicorn import *
import unicorn

from fnmatch import fnmatch
from itertools import groupby
from operator import itemgetter
from collections import namedtuple
from ipaddress import IPv6Address

from .mem import Memory
'''
>>> from iasm.arch import get_engines, Register
>>> from iasm.arch import select_registers, _make_registers_dummy
'''

# Notes:
# Keystone architectures not support by Unicorn
#   KS_ARCH_EVM
#   KS_ARCH_HEXAGON
#   KS_ARCH_SYSTEMZ
#
# Unicorn architectures not supported by Keystone
#   UC_ARCH_M68K
#
# Architectures without 'const' module but supported by Keystone and Unicorn
#   (KS_ARCH_PPC, UC_ARCH_PPC)
_supported_archs = {
    'arm': (KS_ARCH_ARM, UC_ARCH_ARM),
    'arm64': (KS_ARCH_ARM64, UC_ARCH_ARM64),
    'mips': (KS_ARCH_MIPS, UC_ARCH_MIPS),
    'sparc': (KS_ARCH_SPARC, UC_ARCH_SPARC),
    'x86': (KS_ARCH_X86, UC_ARCH_X86),
}

_supported_regs = {
    'arm': (
        unicorn.arm_const, 'UC_ARM_REG_', set(), 'r15', {
            'r9': 'sb',
            'r11': 'fp',
            'r12': 'ip',
            'r13': 'sp',
            'r14': 'lr',
            'r15': 'pc'
        }, ["r[0-9]", "r1*"]
    ),
    'arm64': (
        unicorn.arm64_const, 'UC_ARM64_REG_', set(), 'r15', {
            'r9': 'sb',
            'r11': 'fp',
            'r12': 'ip',
            'r13': 'sp',
            'r14': 'lr',
            'r15': 'pc'
        }, ["r[0-9]", "r1*"]
    ),
    'mips': (unicorn.mips_const, 'UC_MIPS_REG_', set(), 'pc', {}, ['pc']),
    'sparc': (unicorn.sparc_const, 'UC_SPARC_REG_', set(), 'pc', {}, ['pc']),
    'x86': (
        unicorn.x86_const, 'UC_X86_REG_', {'MSR'}, {
            '32': 'eip',
            '64': 'rip'
        }, {}, ["e?x", "esi", "edi", "eip"]
    ),
}

# Notes:
# Unicorn modes not supported by Keystone
#   UC_MODE_MCLASS
_supported_modes = {
    '16': (KS_MODE_16, UC_MODE_16),
    '32': (KS_MODE_32, UC_MODE_32),
    '64': (KS_MODE_64, UC_MODE_64),
    'arm': (KS_MODE_ARM, UC_MODE_ARM),
    'big': (KS_MODE_BIG_ENDIAN, UC_MODE_BIG_ENDIAN),
    'litte': (KS_MODE_LITTLE_ENDIAN, UC_MODE_LITTLE_ENDIAN),
    'micro': (KS_MODE_MICRO, UC_MODE_MICRO),
    'mips3': (KS_MODE_MIPS3, UC_MODE_MIPS3),
    'mips32': (KS_MODE_MIPS32, UC_MODE_MIPS32),
    'mips32r6': (KS_MODE_MIPS32R6, UC_MODE_MIPS32R6),
    'mips64': (KS_MODE_MIPS64, UC_MODE_MIPS64),
    'ppc32': (KS_MODE_PPC32, UC_MODE_PPC32),
    'ppc64': (KS_MODE_PPC64, UC_MODE_PPC64),
    'qpx': (KS_MODE_QPX, UC_MODE_QPX),
    'sparc32': (KS_MODE_SPARC32, UC_MODE_SPARC32),
    'sparc64': (KS_MODE_SPARC64, UC_MODE_SPARC64),
    'thumb': (KS_MODE_THUMB, UC_MODE_THUMB),
    'v8': (KS_MODE_V8, UC_MODE_V8),
    'v9': (KS_MODE_V9, UC_MODE_V9),
}


class Register(namedtuple('P', ('mu', 'name', 'const', 'alias'))):
    ''' A representation of a CPU register.

        Given a CPU emulator like Unicorn, build a representation in
        Python of a CPU register.

        >>> import unicorn
        >>> _, mu, regs, pc, mem = get_engines('x86', '32')
        >>> reg = Register(mu, 'eax', unicorn.x86_const.UC_X86_REG_EAX, None)

        >>> reg
        eax = 0

        >>> reg.val = 15
        >>> reg.val
        15

        >>> reg
        eax = f

        `get_engines` already loads and creates all the registers for you
        and packs them in a list (returned by the function)

        >>> regs[50]
        eax = f

        While both have the same value and therefore they are equals,
        they are different Python objects

        >>> regs[50] == reg
        True

        >>> regs[50] is reg
        False

        A note about the representation of the register. They are
        represented using the IPv6 compressed notation: hexadecimal with
        ":" splitting each 4 numbers and four zeros are compressed to just one.

        >>> reg.val = 0x41424344
        >>> reg
        eax = 4142:4344

        >>> reg.val = 0x1000000
        >>> reg
        eax = 100:0

        This means that all the registers are assumed to be of 16 bytes like
        an IPv6.

        In this notation the longest sequence of zeros is compressed with "::".
        Because all the registers in the real life are 8 bytes or less, the
        longest sequence is at the begin (left).

        For simplification this "::" is removed if it is at the begin. Also
        while an IPv6 full of zeros is represented by a single "::" we prefered
        to use "0".

        Besides the name, the register can have an alias. This changes only
        how it is displayed:

        >>> Register(mu, 'eax', unicorn.x86_const.UC_X86_REG_EAX, "xyz")
        eax/xyz = 100:0
        '''
    @property
    def val(self):
        return self.mu.reg_read(self.const)

    @val.setter
    def val(self, v):
        self.mu.reg_write(self.const, v)

    def repr_val(self):
        v = self.val
        if isinstance(v, int):
            return self._repr_val(v)
        elif isinstance(v, tuple):
            return '(' + ', '.join(self._repr_val(i) for i in v) + ')'
        else:
            raise Exception(
                "Unknown register type'%s' for '%s'" % (type(v), self.name)
            )

    def display_name(self):
        return ("%s/%s" % (self.name, self.alias)) if self.alias else self.name

    def _repr_val(self, v):
        if v == 0:
            return "0"
        r = IPv6Address(v).compressed
        return r.lstrip(":") if r.startswith("::") else r

    def __repr__(self):
        return "%s = %s" % (self.display_name(), self.repr_val())

    def __hash__(self):
        return hash((self.name, self.val))

    def __eq__(self, other):
        if not isinstance(other, Register):
            return False
        return hash(self) == hash(other)


class _RegisterDummy(Register):
    @property
    def val(self):
        return self._val

    @val.setter
    def val(self, v):
        self._val = v


def _make_registers_dummy(names, values=None):
    regs = [_RegisterDummy(None, n, None, None) for n in names]
    if values:
        for r, v in zip(regs, values):
            r.val = v
    else:
        for r in regs:
            r.val = 0

    return regs


def get_registers(mu, arch_name, mode_name):
    mod, regprefix, ignore, pc, aliasses, _ = _supported_regs[arch_name]
    if isinstance(pc, dict):
        pc = pc[mode_name]

    const_names = [n for n in dir(mod) if n.startswith(regprefix)]
    const_names.sort()

    regnames = [n.replace(regprefix, '') for n in const_names]
    consts = [getattr(mod, n) for n in const_names]

    regs = [
        Register(mu, name.lower(), const, aliasses.get(name.lower(), None))
        for name, const in zip(regnames, consts) if name not in ignore
    ]

    return regs, next((r for r in regs if r.name == pc), None)


def select_registers(regs, globs):
    ''' Filter the registers by name following the globs expressions
        (fnmatch).

        >>> regs = _make_registers_dummy(["eax", "ebx", "eip", "esi"])

        Use '?' as a wildcard for a single character and '*' for zero or
        more characters:

        >>> list(select_registers(regs, ['e?x']))
        [eax = 0, ebx = 0]

        >>> list(select_registers(regs, ['e*']))
        [eax = 0, ebx = 0, eip = 0, esi = 0]

        >>> list(select_registers(regs, ['*i*']))
        [eip = 0, esi = 0]

        Charsets can be used with "[seq]" and "[!seq]".

        >>> list(select_registers(regs, ['e[acde]x']))
        [eax = 0]

        >>> list(select_registers(regs, ['e[!acde]x']))
        [ebx = 0]

        Exact names can be used as well:

        >>> list(select_registers(regs, ['eip']))
        [eip = 0]

        Several globs can be applied at the same time: any
        register matching at least one of the globs will be returned

        >>> list(select_registers(regs, ["eax", "ebx"]))
        [eax = 0, ebx = 0]

        A glob prefixed with "!" will negate the match. This is a way
        to block registers matched by a previous glob:

        >>> list(select_registers(regs, ["e*", "!eip"]))
        [eax = 0, ebx = 0, esi = 0]

        The registers allowed by globs determine also the order: registers
        allowed first appear before.

        >>> list(select_registers(regs, ["e*", "!e?x", "eax"]))
        [eip = 0, esi = 0, eax = 0]

        If not glob is given no register is selected:

        >>> list(select_registers(regs, []))
        []
    '''

    if not globs:
        return iter(list())

    selected = []
    for g in globs:
        if g[0] == "!":
            selected = [r for r in selected if not fnmatch(r.name, g[1:])]
        else:
            more = [
                r for r in regs if r not in selected and fnmatch(r.name, g)
            ]
            selected += more

    return selected


def get_engines(arch_name, mode_name):
    ''' Build and get the Keystone and Unicorn engines for the
        given archicture name and mode.

        >>> ks, mu, regs, pc, mem = get_engines('x86', '32')
        >>> ks
        <...>keystone<...>
        >>> mu
        <...>unicorn<...>

        The third result is a ordered list of the registers
        for the given architecture:

        >>> regs[50]
        eax = 0

        And the fourth is the program counter register:

        >>> pc
        eip = 0
    '''
    arch_ks, arch_uc = _supported_archs[arch_name]
    mode_ks, mode_uc = _supported_modes[mode_name]

    ks = Ks(arch_ks, mode_ks)
    mu = Uc(arch_uc, mode_uc)

    # Note: this fails ks.syntax = KS_OPT_SYNTAX_GAS or KS_OPT_SYNTAX_NASM

    regs, pc = get_registers(mu, arch_name, mode_name)
    mem = Memory(mu)
    return ks, mu, regs, pc, mem