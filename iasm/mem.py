from unicorn import UC_PROT_ALL
from bisect import bisect_right
import xview
'''
>>> from iasm.arch import get_engines
>>> from iasm.mem import Memory

>>> _, mu, _, _, _ = get_engines('x86', '32')
>>> mu.mem_map(0x2000, 0x2000)
'''


class Bytearray(bytearray):
    def __repr__(self):
        r = super().__repr__()
        assert r.startswith("bytearray(b") or r.startswith("Bytearray(b")
        return "[%s]" % r[12:-2]

    def _conf(self, mu, arch, mode, addr):
        self._mu, self._arch, self._mode, self._addr = mu, arch, mode, addr

    def hex(self):
        xview.hexdump(memoryview(self), start_addr=self._addr, compress=True)

    def disass(self, endianess='=', arch=None, mode=None):
        extra_kargs = {'arch': arch or self._arch, 'mode': mode or self._mode}
        xview.display(
            'uu',
            bytes(self),
            start_addr=self._addr,
            endianess=endianess,
            extra_kargs=extra_kargs
        )

    def save(self, fname, mode='wb'):
        with open(fname, mode) as f:
            f.write(self)
        print("Saved %i bytes" % len(self))

    def load(self, fname, mode='rb'):
        with open(fname, mode) as f:
            data = f.read()

        if len(data) > len(self):
            raise ValueError(
                "The read %i bytes do not fit in the allocated %i bytes" %
                (len(data), len(self))
            )

        self._mu.mem_write(self._addr, data)
        print("Loaded %i bytes" % len(data))


class Memory:
    def __init__(self, mu, arch, mode):
        self._mu = mu
        self._arch = arch
        self._mode = mode

    def _unpack_index(self, ix):
        ''' Given an index, unpack it into a tuple with the start and
            end addresses and the element size.

            A single address is seen as a region of 1 byte:

            >>> m = Memory(mu, 'x86', '32')
            >>> m._unpack_index(4)
            (4, 5, None)

            Slice objects can be used as well:

            >>> m._unpack_index(slice(0, 8))
            (0, 8, None)

            When the start or the stop of a slice object is missing,
            None is returned:

            >>> m._unpack_index(slice(9))
            (None, 9, None)

            >>> m._unpack_index(slice(3, None))
            (3, None, None)

            But the start and the stop addresses cannot be both None:

            >>> m._unpack_index(slice(None, None))
            <...>
            IndexError: You need to specify at least the begin or end address.

            The step attribute of the slice is not supported:

            >>> m._unpack_index(slice(None, 9, 4))
            <...>
            TypeError: Unsupported step parameter '<class 'int'>'.

            The implementation only supports for non-negative addresses:

            >>> m._unpack_index(slice(-1, None))
            <...>
            IndexError: Addresses must be non-negative.

            >>> m._unpack_index(slice(1, -10))
            <...>
            IndexError: Addresses must be non-negative.

            And the stop address must be greather or equal than the start
            address:

            >>> m._unpack_index(slice(1, 1))
            <...>
            IndexError: Start address cannot be greather or equal to the stop address, [0x1-0x1)

        '''

        if not isinstance(ix, (int, slice)):
            raise TypeError("Unsupported index type '%s'." % type(ix))

        if isinstance(ix, int):
            ix = slice(ix, ix + 1)

        assert isinstance(ix, slice)

        if ix.start is None and ix.stop is None:
            raise IndexError(
                "You need to specify at least the begin or end address."
            )

        if (
            (ix.start is not None and ix.start < 0)
            or (ix.stop is not None and ix.stop < 0)
        ):
            raise IndexError("Addresses must be non-negative.")

        if (ix.start is not None and ix.stop is not None):
            if (ix.start >= ix.stop):
                raise IndexError(
                    "Start address cannot be greather or equal to the stop address, %s"
                    % self._str_range(ix.start, ix.stop)
                )

        if ix.step is not None:
            raise TypeError("Unsupported step parameter '%s'." % type(ix.step))

        return ix.start, ix.stop, ix.step

    def _find_mapped_region_that_contains(self, addr):
        ''' Find the memory region mapped that contains the given
            address.

            >>> m = Memory(mu, 'x86', '32')
            >>> list(mu.mem_regions())
            [(8192, 16383, 7)]

            The address may be mapped:

            >>> m._find_mapped_region_that_contains(0x2100)
            (8192, 16383, 7)

            >>> m._find_mapped_region_that_contains(0x2000)
            (8192, 16383, 7)

            >>> m._find_mapped_region_that_contains(0x80000) is None
            True

            >>> m._find_mapped_region_that_contains(0x1000) is None
            True
        '''

        regions = list(sorted(self._mu.mem_regions()))
        if not regions:
            return None

        begins = [m[0] for m in regions]

        at = bisect_right(begins, addr)
        if at == 0:
            return None

        region = regions[at - 1]
        if region[0] <= addr <= region[1]:
            return region

        return None

    def _str_range(self, start, stop):
        msg = '['
        msg += '...' if start is None else hex(start)
        msg += "-"
        msg += '...' if stop is None else hex(stop)
        msg += ')'

        return msg

    def _str_region(self, region):
        msg = '['
        msg += hex(region[0])
        msg += "-"
        msg += hex(region[1])
        msg += '] (sz '
        msg += hex(self._size_of_region(region))
        msg += ')'

        return msg

    def _find_mapped_subregion(self, start, stop):
        ''' Given an index, find that mapped subregion that contains
            the address/range of addresses.

            >>> m = Memory(mu, 'x86', '32')
            >>> m
            [0x2000-0x3fff] (sz 0x2000)

            Subregion of 1 byte:

            >>> m._str_region(m._find_mapped_subregion(0x2001, 0x2002))
            '[0x2001-0x2001] (sz 0x1)'

            Subregion of 0x1000 bytes:

            >>> m._str_region(m._find_mapped_subregion(0x2002, 0x3002))
            '[0x2002-0x3001] (sz 0x1000)'

            Note how the start address is inclusive and the stop address
            is exclusive like Python ranges/slices.

            But the returned memory region has the begin and end addresses
            both inclusive.

            The start or the stop addresses can be None meaning the begin
            or the end of the full mapped region:

            >>> m._str_region(m._find_mapped_subregion(None, 0x3000))
            '[0x2000-0x2fff] (sz 0x1000)'

            >>> m._str_region(m._find_mapped_subregion(0x2002, None))
            '[0x2002-0x3fff] (sz 0x1ffe)'

            If no region is found or the range given has a subrange of
            unmapped memory, raise an error:

            >>> m._find_mapped_subregion(0x8000, 0x9000)
            <...>
            IndexError: Region [0x8000-0x9000) not mapped

            >>> m._find_mapped_subregion(0x2000, 0x9000)
            <...>
            IndexError: Memory region '[0x2000-0x9000)' is partially mapped. Region mapped is [0x2000-0x3fff] (sz 0x2000).

            >>> m._find_mapped_subregion(0x1000, 0x3000)
            <...>
            IndexError: Memory region '[0x1000-0x3000)' is partially mapped. Region mapped is [0x2000-0x3fff] (sz 0x2000).

        '''

        if start is not None:
            region = self._find_mapped_region_that_contains(start)

            if not region:
                if stop is not None:
                    region = self._find_mapped_region_that_contains(stop - 1)

                if region:
                    err = IndexError(
                        "Memory region '%s' is partially mapped. Region mapped is %s."
                        % (
                            self._str_range(start,
                                            stop), self._str_region(region)
                        )
                    )
                    err.mapped_region = region
                    raise err
        else:
            assert stop is not None
            region = self._find_mapped_region_that_contains(stop - 1)

        if not region:
            err = IndexError(
                "Region %s not mapped" % self._str_range(start, stop)
            )
            err.mapped_region = None
            raise err

        start = start or region[0]
        stop = stop or (region[1] + 1)

        if not (region[0] <= start and stop <= region[1] + 1):
            err = IndexError(
                "Memory region '%s' is partially mapped. Region mapped is %s."
                % (self._str_range(start, stop), self._str_region(region))
            )
            err.mapped_region = region
            raise err

        return (start, stop - 1, region[2])

    def _size_of_region(self, region):
        return region[1] - region[0] + 1

    def __getitem__(self, ix):
        ''' Get the mutable bytes of a (sub)region mapped, indexed by <ix>.

            >>> m = Memory(mu, 'x86', '32')
            >>> list(mu.mem_regions())
            [(8192, 16383, 7)]

            Single byte:

            >>> m[0x2000]
            [\x00]

            Substring:

            >>> m[0x2000:0x2004]
            [\x00\x00\x00\x00]
        '''
        start, stop, elem_sz = self._unpack_index(ix)
        region = self._find_mapped_subregion(start, stop)

        mem_sz = self._size_of_region(region)
        b = Bytearray(self._mu.mem_read(region[0], mem_sz))
        b._conf(self._mu, self._arch, self._mode, region[0])
        return b

    def __setitem__(self, ix, val):
        ''' Set a value in a memory mapped region.

            >>> m = Memory(mu, 'x86', '32')
            >>> m
            [0x2000-0x3fff] (sz 0x2000)

            >>> m[0x2003] = b'\x01'
            >>> m[0x2000:0x2005]
            [\x00\x00\x00\x01\x00]

            More than one byte can be set if the sizes of the region and the
            input match:

            >>> m[0x2000:0x2004] = b'\x02' * 4
            >>> m[0x2000:0x2005]
            [\x02\x02\x02\x02\x00]

            >>> m[0x2000:0x2004] = b'\x00' * 2
            <...>
            ValueError: Mismatch sizes: trying to set 0x2 bytes into mapped region [0x2000-0x2003] (sz 0x4).

            If an integer is used, the whole region is set to that value
            (like memset)

            >>> m[0x2000:0x2004] = 0
            >>> m[0x2000:0x2005]
            [\x00\x00\x00\x00\x00]

            >>> m[0x2000:0x2004] = 2
            >>> m[0x2000:0x2005]
            [\x02\x02\x02\x02\x00]

            If the region is not mapped, it is automatically mapped:

            >>> m
            [0x2000-0x3fff] (sz 0x2000)

            >>> m[0x0000:0x1000] = 0
            Mapping memory region [0x0-0xfff] (sz 0x1000)

            >>> m
            [0x0-0xfff] (sz 0x1000)
            [0x2000-0x3fff] (sz 0x2000)

            If the region overlaps with a previous mapped memory, an error is
            raised:

            >>> m[0x1000:0x3000] = 1
            <...>
            IndexError: Memory region '[0x1000-0x3000)' is partially mapped. Region mapped is [0x2000-0x3fff] (sz 0x2000).
            The range [0x1000-0x3000) cannot be mapped because it overlaps with a previous mapped region [0x2000-0x3fff] (sz 0x2000).

            The start or the stop addresses can be ommited to set "from the
            begin" or "to the end" of the region.

            >>> m[0x2002:] = 4
            >>> m[0x2000:0x2005]
            [\x02\x02\x04\x04\x04]

            >>> m[:0x2002] = 8
            >>> m[0x2000:0x2005]
            [\x08\x08\x04\x04\x04]

            When setting bytes the sizes must match except with the stop address
            is missing. In this case works like memcpy

            >>> m[0x2002:] = b'\x03\x03'
            >>> m[0x2000:0x2005]
            [\x08\x08\x03\x03\x04]

            However new mapping cannot be created with this syntax:

            >>> m[:0x9000] = 8
            <...>
            IndexError: Region [...-0x9000) not mapped
            The range [...-0x9000) cannot be mapped because one of its ends is not fixed.

            >>> m[0x9000:] = 8
            <...>
            IndexError: Region [0x9000-...) not mapped
            The range [0x9000-...) cannot be mapped because one of its ends is not fixed.

            >>> del m[0:]
        '''

        start, stop, elem_sz = self._unpack_index(ix)
        try:
            region = self._find_mapped_subregion(start, stop)
        except IndexError as err:
            if not hasattr(err, 'mapped_region'):
                raise

            partial_mapped = getattr(err, 'mapped_region')

            if partial_mapped is None:
                if start is None or stop is None:
                    msg = str(err) + (
                        "\nThe range %s cannot be mapped because one of its ends is not fixed."
                        % self._str_range(start, stop)
                    )
                    raise IndexError(msg) from None
                else:
                    proto_region = (start, stop - 1, UC_PROT_ALL)
                    print(
                        "Mapping memory region %s" %
                        (self._str_region(proto_region))
                    )

                    self._mu.mem_map(
                        start, self._size_of_region(proto_region), UC_PROT_ALL
                    )
                    region = proto_region
            else:
                msg = str(err) + (
                    "\nThe range %s cannot be mapped because it overlaps with a previous mapped region %s."
                    % (
                        self._str_range(start, stop),
                        self._str_region(partial_mapped)
                    )
                )
                raise IndexError(msg) from None

        # memset functionality
        mem_sz = self._size_of_region(region)
        if isinstance(val, int):
            step = 0x2000  # 8k
            if val:
                data = bytes([val]) * step
            else:
                data = bytes(step)  # null initialized
            for addr in range(region[0], region[1] + 1, step):
                if addr + step > region[1] + 1:
                    data = data[:region[1] - addr + 1]
                self._mu.mem_write(addr, data)

        elif stop is None:
            # memcpy
            self._mu.mem_write(region[0], val)
        else:
            if mem_sz != len(val):
                raise ValueError(
                    "Mismatch sizes: trying to set %s bytes into mapped region %s."
                    % (hex(len(val)), self._str_region(region))
                )
            self._mu.mem_write(region[0], val)

    def __delitem__(self, ix):
        ''' Unmap a subregion of memory.

            >>> mu.mem_map(0x8000, 0x24000)
            >>> m = Memory(mu, 'x86', '32')
            >>> m
            [0x2000-0x3fff] (sz 0x2000)
            [0x8000-0x2bfff] (sz 0x24000)

            A subregion can be in the middle of a mapped region
            (which it is splitted):

            >>> del m[0x10000:0x12000]
            >>> m
            [0x2000-0x3fff] (sz 0x2000)
            [0x8000-0xffff] (sz 0x8000)
            [0x12000-0x2bfff] (sz 0x1a000)

            The subregion can be at the begin or at the end of a region:

            >>> del m[0x8000:0x9000]
            >>> del m[0x16000:0x2c000]
            >>> m
            [0x2000-0x3fff] (sz 0x2000)
            [0x9000-0xffff] (sz 0x7000)
            [0x12000-0x15fff] (sz 0x4000)

            To unmap full regions just set the begin or the end addresses:

            >>> del m[0x9000:]
            >>> del m[:0x16000]
            >>> m
            [0x2000-0x3fff] (sz 0x2000)

        '''

        start, stop, elem_sz = self._unpack_index(ix)
        region = self._find_mapped_subregion(start, stop)

        mem_sz = self._size_of_region(region)
        try:
            self._mu.mem_unmap(region[0], mem_sz)
        except Exception as err:
            print(
                "Memory region %s couldn't be unmapped: %s\nMay be the address is not aligned or the size if not multiple of the page size?"
                % (self._str_region(region), err)
            )

    def __repr__(self):
        return '\n'.join(
            self._str_region(r) for r in sorted(self._mu.mem_regions())
        )
