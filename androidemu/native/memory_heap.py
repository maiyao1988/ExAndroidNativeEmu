from collections import OrderedDict
import traceback
from unicorn import *
from ..internal import align

PAGE_SIZE = 0x1000


class UnicornSimpleHeap:

    @staticmethod
    def is_contains(addr1, end1, addr2, end2):
        return (addr1 <= addr2 and end1 >= end2)
    #

    def __init__(self, mu, heap_min_addr, heap_max_addr):
        self.__mu = mu
        self._heap_min_addr = heap_min_addr
        self._heap_max_addr = heap_max_addr

    def map(self, address, size, prot=UC_PROT_READ | UC_PROT_WRITE):
        if size <= 0:
            raise Exception('Heap map size was <= 0.')
        print("map addr:0x%08X, sz:0x%08X"%(address, size))
        #traceback.print_stack()
        address, size = align(address, size, True)
        try:
            if (address == 0):
                regions = []
                for r in self.__mu.mem_regions():
                    regions.append(r)
                #
                regions.sort()
                last_end = -1
                for r in regions:
                    #print("region begin :0x%08X end:0x%08X, prot:%d"%(r[0], r[1], r[2]))
                    #取最大的end，在后面直接map出来
                    if (r[1] <= self._heap_min_addr):
                        continue
                    if (last_end < 0):
                        last_end = r[1]+1
                        continue
                    else:
                        empty_sz =  r[0] - last_end
                        if (empty_sz >= size):
                            #print (hex(empty_sz))
                            print(hex(r[0]))
                            print(hex(last_end))
                            break
                        last_end = r[1]+1
                    #
                #
                if (last_end < 0):
                    last_end = self._heap_min_addr
                #
                print("before mem_map addr:0x%08X, sz:0x%08X"%(last_end, size))

                self.__mu.mem_map(last_end, size, perms=prot)
                return last_end
            #
            else:
                #MAP_FIXED
                try:
                    self.__mu.mem_map(address, size, perms=prot)
                except unicorn.UcError as e:
                    if (e.errno == UC_ERR_MAP):
                        blocks = set()
                        extra_protect = set()
                        for b in range(address, address+size, 0x1000):
                            blocks.add(b)
                        #
                        for r in self.__mu.mem_regions():
                            #修改属性
                            raddr = r[0]
                            rend = r[1]+1
                            for b in range(raddr, rend, 0x1000):
                                if (b in blocks):
                                    blocks.remove(b)
                                    extra_protect.add(b)
                                #
                            #
                        #
                        for b_map in blocks:
                            self.__mu.mem_map(b_map, 0x1000, prot)
                        #
                        for b_protect in extra_protect:
                            self.__mu.mem_protect(b_protect, 0x1000, prot)
                        #
                    #
                    return address
                #
            #
        except unicorn.UcError as e:
            for r in self.__mu.mem_regions():
                print("region begin :0x%08X end:0x%08X, prot:%d"%(r[0], r[1], r[2]))
            #
            raise
        #
        for r in self.__mu.mem_regions():
            print("region begin :0x%08X end:0x%08X, prot:%d"%(r[0], r[1], r[2]))
        #
    #

    def protect(self, addr, len_in, prot):
        if not self.is_multiple(addr):
            raise Exception('addr was not multiple of page size (%d, %d).' % (addr, PAGE_SIZE))

        if not self.is_multiple(len_in):
            raise Exception('len_in was not multiple of page size (%d, %d).' % (addr, PAGE_SIZE))

        try:
            self.__mu.mem_protect(addr, len_in, prot)
        except unicorn.UcError as e:
            #TODO:just for debug
            raise
            return -1
        #
        return 0

    def unmap(self, addr, size):
        if not self.is_multiple(addr):
            raise Exception('addr was not multiple of page size (%d, %d).' % (addr, PAGE_SIZE))

        _, size = align(addr, size, True)
        try:
            print("unmap 0x%08X sz=0x0x%08X end=0x0x%08X"%(addr,size, addr+size))
            self.__mu.mem_unmap(addr, size)
        except unicorn.UcError as e:
            #TODO:just for debug

            for r in self.__mu.mem_regions():
                print("region begin :0x%08X end:0x%08X, prot:%d"%(r[0], r[1], r[2]))
            #
            raise
            return -1
        #
        return 0

    def check_addr(self , addr, prot):
        for r in self.__mu.mem_regions():
            if (addr>=r[0] and addr < r[1] and prot & r[2]):
                return True
        #
        return False
    #

    @staticmethod
    def is_multiple(addr):
        return addr % PAGE_SIZE == 0

