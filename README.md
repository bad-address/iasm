# ``iasm``

`iasm` is an *interactive assembler* for x86, arm, mips,
and sparc.

```shell
$ iasm -a arm -m arm
Mapping memory region [0x1000000-0x11fffff] (sz 0x200000)
------  -  ------  -  ------  -  ------  -----
    r0  0  r1      0  r2      0  r3      0
    r4  0  r5      0  r6      0  r7      0
    r8  0  r9/sb   0  r10     0  r11/fp  0
r12/ip  0  r13/sp  0  r14/lr  0  r15/pc  100:0
------  -  ------  -  ------  -  ------  -----
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
100:0> ;! M[0x1000:0x2000] = 0  # map and initialize
Mapping memory region [0x1000-0x1fff] (sz 0x1000)

100:0> ;! M[0x1050:0x1055] = 0x41       # write like 'memset'
100:0> ;! M[0x1055:0x105a] = b'B' * 5   # write like 'memcpy'

100:0> ;! M[0x1050:0x105a]     # read
[AAAAABBBBB]

100:0> ;! M    # list mapped pages
[0x1000-0x1fff] (sz 0x1000)
[0x1000000-0x11fffff] (sz 0x200000)

100:0> ;! del M[0x1000:0x2000]    # unmap
```

### Allocate stack

To allocate the stack and setup the (Arm) registers just run:

```python
100:0> ;! M[0x1000:0x2000] = 0
Mapping memory region [0x1000-0x1fff] (sz 0x1000)

100:0> ;! fp = sp = 0x2000
```

Now, play with it and practice your (Arm) assembly:

```nasm
100:0> mov r0, #4
100:0> mov r1, #8
100:0> push {r0, r1}
```

And check the stack (was `r0` pushed before `r1` or not? Check it!)

```python
100:0> ;! M[sp:]   # from sp to the end of the mapped page
[\x04\x00\x00\x00\x08\x00\x00\x00]
```

### Initialization script

Write in a file all the initialization like the stack allocation and
load it from the command line with `-i`.

```shell
$ echo ';! r0 = r1 = r2 = 8' > init

$ iasm -a arm -m arm -i init
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
100:0> mul ?
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
$ iasm -a arm -m arm -r 'r[0-9]'
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

## How to install it?

```shell
$ pip install iasm          # byexample: +skip
```

