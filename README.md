# ``iasm``

`iasm` is an *interactive assembler* for x86, arm, mips,
and sparc.

```shell
$ iasm -a arm -m arm
Mapping memory region [0x1000000-0x11fffff] (sz 0x200000)
Mapping memory region [0x2000-0x3fff] (sz 0x2000)
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

```
100:0> mov r0, 12
------  -  ------  -  ------  -  ------  -----
    r0  c  r1      0  r2      0  r3      0
    r4  0  r5      0  r6      0  r7      0
    r8  0  r9/sb   0  r10     0  r11/fp  0
r12/ip  0  r13/sp  0  r14/lr  0  r15/pc  100:0
------  -  ------  -  ------  -  ------  -----
```

As you probably noted the registers are printed in a "compressed hex"
notation.

The value is in hexadecimal and every 4 digits a ":" is put with
four zeros compressed with a single "0". The value of `r15` is
`0x1000000` for example.

Each architecture has its own set of registers. `iasm` shows only a few
by default but you can change them from the command line.

```shell
$ iasm -a arm -m arm -r 'r[0-9]' -r 'd?'
Mapping memory region [0x1000000-0x11fffff] (sz 0x200000)
Mapping memory region [0x2000-0x3fff] (sz 0x2000)
--  -  -----  -  --  -  --  -
r0  0  r1     0  r2  0  r3  0
r4  0  r5     0  r6  0  r7  0
r8  0  r9/sb  0  d0  0  d1  0
d2  0  d3     0  d4  0  d5  0
d6  0  d7     0  d8  0  d9  0
--  -  -----  -  --  -  --  -
100:0>
```

To select a register `iasm` uses *globs* expressions. See the
documentation of
[fnmatch](https://docs.python.org/3/library/fnmatch.html) but in short
`[n-m]` define a range, `?` servers for a single char wildcard and `*`
for zero or more.

For convenience you can read and write the registers and memory with
a more high-level language, Python of course.

Just type `;!` and then your code.

Write a register:

```
100:0> ;! r0 = 8
------  -  ------  -  ------  -  ------  -----
    r0  8  r1      0  r2      0  r3      0
    r4  0  r5      0  r6      0  r7      0
    r8  0  r9/sb   0  r10     0  r11/fp  0
r12/ip  0  r13/sp  0  r14/lr  0  r15/pc  100:0
------  -  ------  -  ------  -  ------  -----
```

Write memory (allocate if needed):

```
100:0> ;! M[0x1000:0x2000] = 0
Mapping memory region [0x1000-0x1fff] (sz 0x1000)
------  -  ------  -  ------  -  ------  -----
    r0  8  r1      0  r2      0  r3      0
    r4  0  r5      0  r6      0  r7      0
    r8  0  r9/sb   0  r10     0  r11/fp  0
r12/ip  0  r13/sp  0  r14/lr  0  r15/pc  100:0
------  -  ------  -  ------  -  ------  -----
```

Read memory:

```
100:0> ;! r0 = M[0x1000]
------  -  ------  -  ------  -  ------  -----
    r0  0  r1      0  r2      0  r3      0
    r4  0  r5      0  r6      0  r7      0
    r8  0  r9/sb   0  r10     0  r11/fp  0
r12/ip  0  r13/sp  0  r14/lr  0  r15/pc  100:0
------  -  ------  -  ------  -  ------  -----
```

## How to install it?

```shell
$ pip install iasm          # byexample: +skip
```

