from keystone import *
from unicorn import *
import unicorn

from fnmatch import fnmatch
from itertools import groupby
from operator import itemgetter
from collections import namedtuple, OrderedDict
from ipaddress import IPv6Address
from bitstring import Bits
from functools import partial

from .mem import Memory
'''
>>> from iasm.arch import get_engines, Register, FlagRegister, _get_flag
>>> from iasm.arch import select_registers, _make_registers_dummy
>>> from collections import OrderedDict
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
        }, ["r[0-9]", "r1*", "cpsr"], {
            'cpsr': (
                32,
                OrderedDict(
                    [
                        ('N', 31),
                        ('Z', 30),
                        ('C', 29),
                        ('V', 28),
                        ('Q', 27),
                        ('J', 24),
                        (1, None),
                        ('GE', slice(16, 20)),
                        (2, None),
                        ('E', 9),
                        ('A', 8),
                        ('I', 7),
                        ('F', 6),
                        ('T', 5),
                        (3, None),
                        ('M', slice(0, 5)),
                        (4, None),
                        ('IT', (slice(25, 27), slice(10, 16))),
                        (5, None),
                        ('...........', slice(20, 24)),
                    ]
                )
            )
        }
    ),
    'arm64': (
        unicorn.arm64_const, 'UC_ARM64_REG_', set(), 'r15', {
            'r9': 'sb',
            'r11': 'fp',
            'r12': 'ip',
            'r13': 'sp',
            'r14': 'lr',
            'r15': 'pc'
        }, ["r[0-9]", "r1*", "cpsr"], {
            'cpsr': (
                32,
                OrderedDict(
                    [
                        ('N', 31),
                        ('Z', 30),
                        ('C', 29),
                        ('V', 28),
                        ('Q', 27),
                        ('J', 24),
                        (1, None),
                        ('GE', slice(16, 20)),
                        (2, None),
                        ('E', 9),
                        ('A', 8),
                        ('I', 7),
                        ('F', 6),
                        ('T', 5),
                        (3, None),
                        ('M', slice(0, 5)),
                        (4, None),
                        ('IT', (slice(25, 27), slice(10, 16))),
                        (5, None),
                        ('...........', slice(20, 24)),
                    ]
                )
            )
        }
    ),
    'mips': (unicorn.mips_const, 'UC_MIPS_REG_', set(), 'pc', {}, ['pc'], {}),
    'sparc':
    (unicorn.sparc_const, 'UC_SPARC_REG_', set(), 'pc', {}, ['pc'], {}),
    'x86': (
        unicorn.x86_const, 'UC_X86_REG_', {'msr'}, {
            '32': 'eip',
            '64': 'rip'
        }, {}, ["e?x", "esi", "edi", "eip"], {}
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


class Register(
    namedtuple('P', ('mu', 'name', 'const', 'alias', 'f_dscrs', 'sz'))
):
    ''' A representation of a CPU register.

        Given a CPU emulator like Unicorn, build a representation in
        Python of a CPU register.

        >>> import unicorn
        >>> _, mu, regs, pc, mem = get_engines('x86', '32')
        >>> reg = Register(mu, 'eax', unicorn.x86_const.UC_X86_REG_EAX, None, None, None)

        >>> reg
        eax = 0

        >>> reg.val = 15
        >>> reg.val
        15

        >>> reg
        eax = f

        `get_engines` already loads and creates all the registers for you
        and packs them in a list (returned by the function)

        >>> ix = regs.index(reg)
        >>> regs[ix]
        eax = f

        While both have the same value and therefore they are equals,
        they are different Python objects

        >>> regs[ix] == reg
        True

        >>> regs[ix] is reg
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
        while an IPv6 full of zeros is represented by a single "::" we preferred
        to use "0".

        Besides the name, the register can have an alias. This changes only
        how it is displayed:

        >>> Register(mu, 'eax', unicorn.x86_const.UC_X86_REG_EAX, "xyz", None, None)
        eax/xyz = 100:0
        '''
    @property
    def val(self):
        try:
            return self.mu.reg_read(self.const)
        except Exception as err:
            raise Exception(
                f"Register {self.name} ({self.alias}) could not be read under symbolic constant {self.const}."
            ) from err

    @val.setter
    def val(self, v):
        self.mu.reg_write(self.const, v)

    def is_available(self):
        ''' Return if the register can be readed without an error. '''
        try:
            _ = self.val
            return True
        except:
            return False

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

    def __eq__(self, other):
        if not isinstance(other, Register):
            return False

        # compare first the name and only if they match compare
        # their values (fetching the value is expensive so we relay
        # on the short-circuit to not pay the cost on any __eq__ call
        return self.name == other.name and self.val == other.val


def _get_flag(reg, flag_descr, reg_sz):
    ''' Return a Bits representation of a subset of the register <reg>.

        The subset is defined by the flag descriptor assuming a register
        of <reg_sz> size.

        >>> reg = _make_registers_dummy(['cpsr'], [0b1000000000001100])[0]

        An integer means a single bit:

        >>> _get_flag(reg, 0, 16).bin    # LSB
        '0'
        >>> _get_flag(reg, 15, 16).bin    # MSB
        '1'

        A slice object means a range of bits:

        >>> _get_flag(reg, slice(0, 4), 16).bin
        '1100'

        A tuple of integers and slices means a range of bits that
        cannot be represented by a single slice because they are
        non-contiguous.

        >>> _get_flag(reg, (15, 14, slice(0, 4)), 16).bin
        '101100'
        '''
    # Note: we reverse the bits at the begin and then at the end.
    # This allows the indexing notation to put the low numbers (0)
    # on the right to select LSB and the high number (N-1) on the left
    # to select the MSB
    bs = Bits(uint=reg.val, length=reg_sz)[::-1]
    if isinstance(flag_descr, int):
        seq = [bs[flag_descr:flag_descr + 1]]
    elif isinstance(flag_descr, slice):
        seq = [bs[flag_descr]]
    else:
        assert isinstance(flag_descr, tuple)
        seq = [
            (bs[d:d + 1] if isinstance(d, int) else bs[d]) for d in flag_descr
        ]

    assert isinstance(seq, list) and all(isinstance(b, Bits) for b in seq)
    return sum(b[::-1] for b in seq)


class FlagRegister(Register):
    def _define_flags_description(self):
        for name, descr in self.f_dscrs.items():
            if descr is None:
                continue

            fget = partial(_get_flag, flag_descr=descr, reg_sz=self.sz)
            prop = property(fget, doc='Flag %s' % name)
            setattr(self, name, prop)

    def repr_val(self):
        bs = []
        names = []
        for name, descr in self.f_dscrs.items():
            if descr is None:
                bs.append(' ')
                names.append(' ')
                continue

            b = _get_flag(self, flag_descr=descr, reg_sz=self.sz)
            bs.append(b)

            name = name[:len(b.bin)]
            if len(name) < len(b):
                name += " " * (len(b) - len(name))
            names.append(name)

        up = ''.join(b if b == ' ' else b.bin for b in bs)
        down = ''.join(names)

        return up + '\n' + down

    def __repr__(self):
        ''' Representation of flags

            >>> f_dscrs = OrderedDict([('N', 31), ('Z', 30), (1, None), ('M', slice(0, 5, None))])
            >>> FlagRegister(mu, 'eax', unicorn.x86_const.UC_X86_REG_EAX, None, f_dscrs, 32)
            eax =
            00 00000
            NZ M
            '''
        return "%s =\n%s" % (self.display_name(), self.repr_val())


class _RegisterDummy(Register):
    @property
    def val(self):
        return self._val

    @val.setter
    def val(self, v):
        self._val = v


def _make_registers_dummy(names, values=None):
    regs = [_RegisterDummy(None, n, None, None, None, None) for n in names]
    if values:
        for r, v in zip(regs, values):
            r.val = v
    else:
        for r in regs:
            r.val = 0

    return regs


def get_registers(mu, arch_name, mode_name):
    mod, regprefix, ignore, pc_name, aliasses, _, f_regs = _supported_regs[
        arch_name]
    if isinstance(pc_name, dict):
        pc_name = pc_name[mode_name]

    const_names = [n for n in dir(mod) if n.startswith(regprefix)]
    const_names.sort()

    regnames = [n.replace(regprefix, '') for n in const_names]
    consts = [getattr(mod, n) for n in const_names]

    regs = []
    pc = None
    for name, const in zip(regnames, consts):
        name = name.lower()
        if name in ignore:
            continue

        alias = aliasses.get(name, None)
        if name in f_regs:
            reg_sz, f_dscrs = f_regs[name]
            reg = FlagRegister(mu, name, const, alias, f_dscrs, reg_sz)
            reg._define_flags_description()
        else:
            reg = Register(mu, name, const, alias, None, None)

        if name == pc_name:
            pc = reg

        if not reg.is_available():
            continue

        regs.append(reg)

    return regs, pc


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
        if g and g[0] == "!":
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

        >>> regs[ix]
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
    mem = Memory(mu, arch_name, mode_name)
    return ks, mu, regs, pc, mem
