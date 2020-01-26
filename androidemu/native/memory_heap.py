from collections import OrderedDict
import traceback
from unicorn import *
from ..internal import align

PAGE_SIZE = 0x1000


class UnicornSimpleHeap:

    def __init__(self, mu, heap_min_addr, heap_max_addr):
        self.__mu = mu
        self._heap_min_addr = heap_min_addr
        self._heap_max_addr = heap_max_addr
        self._blocks = OrderedDict()

    def map(self, address, size, prot=UC_PROT_READ | UC_PROT_WRITE):
        if size <= 0:
            raise Exception('Heap map size was <= 0.')
        print("map addr:0x%08X, sz:0x%08X"%(address, size))
        #traceback.print_stack()
        address, size = align(address, size, True)
        data_size = size
        data_addr = None
        if (address == 0):
            available_start = None
            available_size = 0

            # Find empty space big enough for data_size.
            for addr in range(self._heap_min_addr, self._heap_max_addr, PAGE_SIZE):
                if addr in self._blocks:
                    available_start = None
                    available_size = 0
                    continue

                if available_start is None:
                    available_start = addr

                available_size = available_size + PAGE_SIZE

                if available_size == data_size:
                    data_addr = available_start
                    break
        #
        else:
            for addr in range(address, self._heap_max_addr, PAGE_SIZE):
                if (addr in self._blocks):
                    for r in self.__mu.mem_regions():
                        print("region begin :0x%08X end:0x%08X, prot:%d"%(r[0], r[1], r[2]))
                    #

                    raise Exception('Failed to mmap memory on base 0x%08X'%(address, ))
                    return 0
                #
            #
            data_addr = address
        #
        # Check if nothing was found.
        if data_addr is None:
            raise Exception('Failed to mmap memory.')
            return 0
        #

        # Reserve.
        for addr in range(data_addr, data_addr + data_size, PAGE_SIZE):
            self._blocks[addr] = 1
        #
        # Actually map in emulator.
        
        print("before mem_map addr:0x%08X, sz:0x%08X"%(data_addr, data_size))
        r = self.__mu.mem_map(data_addr, data_size, perms=prot)
        return data_addr
    #

    def protect(self, addr, len_in, prot):
        if not self.is_multiple(addr):
            raise Exception('addr was not multiple of page size (%d, %d).' % (addr, PAGE_SIZE))

        if not self.is_multiple(len_in):
            raise Exception('len_in was not multiple of page size (%d, %d).' % (addr, PAGE_SIZE))

        for addr_in in range(addr, addr + len_in - 1, PAGE_SIZE):
            if addr_in in self._blocks:
                self.__mu.mem_protect(addr_in, len_in, prot)

        return True

    def unmap(self, addr, size):
        print("unmap 0x%08X sz=0x0x%08X"%(addr,size))
        if not self.is_multiple(addr):
            raise Exception('addr was not multiple of page size (%d, %d).' % (addr, PAGE_SIZE))

        _, size = align(addr, size, True)
        for addr_in in range(addr, size, PAGE_SIZE):
            if addr_in in self._blocks:
                self.__mu.mem_unmap(addr_in, PAGE_SIZE)
                self._blocks.pop(addr_in)
            else:
                raise Exception('Attempted to unmap memory that was not mapped.')
        return True

    @staticmethod
    def is_multiple(addr):
        return addr % PAGE_SIZE == 0

