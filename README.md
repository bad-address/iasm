# ``iasm``

`iasm` is an *interactive assembler* for x86, arm, mips,
and sparc.

<!--
$ hash iasm   # byexample: +fail-fast
$ export PROMPT_TOOLKIT_NO_CPR=1
-->

```shell
$ iasm -a arm -m arm                      # byexample: +stop-on-silence=1 +term=ansi +stop-signal=eof
Mapping memory region [0x1000000-0x11fffff] (sz 0x200000)
------  -  ------  -  ------  -  ------  -----
    r0  0  r1      0  r2      0  r3      0
    r4  0  r5      0  r6      0  r7      0
    r8  0  r9/sb   0  r10     0  r11/fp  0
r12/ip  0  r13/sp  0  r14/lr  0  r15/pc  100:0
------  -  ------  -  ------  -  ------  -----
----  -------------------------------------
cpsr  010000 0000 01110 10011 00000000 0000
      NZCVQJ GE   EAIFT M     IT       ....
----  -------------------------------------
100:0>
```

Then, type the instructions. Under the hood what your type
is parsed by [keystone](https://www.keystone-engine.org/)
and emulated in a virtual CPU by [unicorn](https://www.unicorn-engine.org/).

## Usage

<img src="https://raw.githubusercontent.com/bad-address/iasm/master/media/demo.gif" alt="Sorry, it seems that you cannot see the demo. Another excuse to install iasm and test it by yourself ;)" width="75%" height="75%">

## How do I get started?

Just install `iasm` with `pip`:

```shell
$ pip install iasm          # byexample: +skip
```

## Features

### Shell

It has syntax highlighting as you write (using [pygments](https://pygments.org/)),
autocompletion and command line history (using [python-prompt-toolkit](https://python-prompt-toolkit.readthedocs.io/en/latest/))

An enhanced replacement for Python's `input` for sure.

By default what you type is assembly code. If you prefix your input with
`;!`  you can enter Python code and access to the registers and memory
easier.

### Memory

`iasm` allows you to map, initialize and read memory pages
from the Python shell:

```python
:> ;! M[0x1000:0x2000] = 0  # map and initialize
Mapping memory region [0x1000-0x1fff] (sz 0x1000)

:> ;! M[0x1050:0x1055] = 0x41       # write like 'memset'
:> ;! M[0x1055:0x105a] = b'B' * 5   # write like 'memcpy'

:> ;! M[0x1050:0x105a]     # read
[AAAAABBBBB]

:> ;! M    # list mapped pages
[0x1000-0x1fff] (sz 0x1000)
[0x1000000-0x11fffff] (sz 0x200000)

:> ;! M[0x1000:0x2000].load("test/ds/foo")  # load from a file
Loaded 60 bytes

:> ;! M[0x1000:0x2000].save("test/ds/dump") # save a dump in a file
Saved 4096 bytes

:> ;! M[0x1000:0x1000+45].hex() # display in hexdump
00001000  31 36 30 34 31 35 31 33  30 38 39 34 37 09 67 65  |1604151308947.ge|
00001010  63 6b 6f 64 72 69 76 65  72 09 49 4e 46 4f 09 4c  |ckodriver.INFO.L|
00001020  69 73 74 65 6e 69 6e 67  20 6f 6e 20 31           |istening on 1   |

:> ;! M[0x1000:0x1000+8].disass()   # disassembly
00001000  ldrtlo  r3, [r0], #-0x631
00001004  teqlo   r1, #0xc400000

:> ;! del M[0x1000:0x2000]    # unmap
```

### Allocate stack

To allocate the stack and setup the (Arm) registers just run:

```python
:> ;! M[0x1000:0x2000] = 0
Mapping memory region [0x1000-0x1fff] (sz 0x1000)

:> ;! fp = sp = 0x2000
```

Now, play with it and practice your (Arm) assembly:

```nasm
:> mov r0, #4
:> mov r1, #8
:> push {r0, r1}
```

And check the stack (was `r0` pushed before `r1` or not? Check it!)

```python
:> ;! M[sp:]   # from sp to the end of the mapped page
[\x04\x00\x00\x00\x08\x00\x00\x00]
```

### Initialization script

Write in a file all the initialization like the stack allocation and
load it from the command line with `-i`.

```shell
$ echo ';! r0 = r1 = r2 = 8' > init

$ iasm -a arm -m arm -i init        # byexample: +stop-on-silence=1 +term=ansi +stop-signal=eof
Mapping memory region [0x1000000-0x11fffff] (sz 0x200000)
------  -  ------  -  ------  -  ------  -----
    r0  8  r1      8  r2      8  r3      0
<...>
```

### Inline documentation

Following the tradition of Python, `iasm` includes documentation for the
assembly instructions.

After the mnemonic type `?` and enter to show it:

```nasm
:> mul ?        ; byexample: +skip
# C6.2.197 - MUL

  Multiply : Rd = Rn * Rm This instruction is an alias of the MADD
  instruction. This means that:
    -  The encodings in this description are named to match the
  encodings of MADD.
    -  The description of MADD gives the operational pseudocode for
  this instruction.
  <...>
```

Basically what I did was to convert to text the manual of reference of
the ISA (typically it is a PDF file) and then parse the text.

I only focused in the documentation of the instructions, the rest is up
to the user to search the complete story in the official documentation.

Currently only Armv8 is supported. Pull requests are welcome!!

### Globs registers

`iasm` allows to select which registers to show using *globs*,
Unix like pattern expressions defined by
[fnmatch](https://docs.python.org/3/library/fnmatch.html).

```shell
$ iasm -a arm -m arm -r 'r[0-9]'        # byexample: +stop-on-silence=1 +term=ansi +stop-signal=eof
Mapping memory region [0x1000000-0x11fffff] (sz 0x200000)
--  -  -----  -  --  -  --  -
r0  0  r1     0  r2  0  r3  0
r4  0  r5     0  r6  0  r7  0
r8  0  r9/sb  0
--  -  -----  -  --  -  --  -
<...>
```

So the expression `r[0-9]` selects all the Arm registers from `r0` to
`r15`.

You can change the set of registers to display from `iasm` with the
`show()` function:

```nasm
:> ;! show('r[0-3]')
--  -  --  -  --  -  --  -
r0  4  r1  8  r2  0  r3  0
--  -  --  -  --  -  --  -
```

If you want to change the register set permanently add `stick=True`:

```nasm
:> ;! show('r[0-3]', stick=True)
--  -  --  -  --  -  --  -
r0  4  r1  8  r2  0  r3  0
--  -  --  -  --  -  --  -

:> mov r2, r1
--  -  --  -  --  -  --  -
r0  4  r1  8  r2  8  r3  0
--  -  --  -  --  -  --  -
```

Call `show(stick=True)` to restore the defaults:

```nasm
:> ;! show(stick=True)
```

### Compressed hex values

32 bit numbers are too large to display (and 64 bit address are
worse!).

Instead, `iasm` shows them as *compressed* hexadecimal numbers.

They are like hexadecimals but the number is split into 4-digits groups
divided by a `:`.

The leading zeros of each group are omitted and if the group is full of
zeros only a single `0` is put and if the group is on the left (more
significant digits), the whole group is omitted.

Here are some examples:

```
0x00000000             0
0x000000ab            ab
0x00ab00cd         ab:cd
0x00ab0000          ab:0
```

### Integration with `byexample`

You can write posts or documents and write examples of `iasm` just like
the README that you are reading right now.

Then you can run [byexample](https://byexamples.github.io/byexample/) to
take these examples and turn them into regression tests.

```shell
$ byexample -l iasm README.md                   # byexample: +skip
File README.md, 17/17 test ran in 1.06 seconds
[PASS] Pass: 16 Fail: 0 Skip: 1
```

See [byexample's support of
iasm](https://byexamples.github.io/byexample/languages/iasm) for the
details.

## How to install it?

```shell
$ pip install iasm          # byexample: +skip

$ iasm -V                   # byexample: +norm-ws
iasm 0.1.0 (Python <...>, Keystone <...>, Unicorn <...>) - GNU GPLv3
Interactive Assembler
Copyright (C) Di Paola Martin - https://github.com/bad-address/iasm
<...>
```

<!--
$ kill -9 $(jobs -p) && wait        # byexample: -skip +pass
-->
