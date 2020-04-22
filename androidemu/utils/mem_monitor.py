import sys
import os
from .debug_utils import *

class MemoryMonitor:
    def __init__(self, emu):
        self.__emu = emu
        self.__has_writed = set()
        self.__read_not_writed = set()
    #

    def feed_write(self, pc, address, size):
        #data = self.__emu.mu.mem_read(address, size)
        for addr in range(address, address+size):
            self.__has_writed.add(addr)
        #
    #

    def feed_read(self, pc, address, size):
        for addr in range(address, address+size):
            if addr not in self.__has_writed:
                self.__read_not_writed.add((addr, pc))
            #
        #
    #

    def dump_read_no_write(self, f):
        name_read = "unknown"
        name_pc ="unknown"
        base_read = 0
        base_pc = 0
        li = list(self.__read_not_writed)
        li.sort()
        for item in li:
            addr = item[0]
            pc = item[1]     
            moudle_mem = get_module_by_addr(self.__emu, addr)
            if (moudle_mem != None):
                name_read = os.path.basename(moudle_mem.filename)
                base_read = moudle_mem.base
            #
            else:
                name_read = "unknown"
                base_read = 0
            #

            moudle_pc = get_module_by_addr(self.__emu, pc)
            
            if (moudle_pc != None):
                name_pc = os.path.basename(moudle_pc.filename)
                base_pc = moudle_pc.base
            #
            else:
                name_pc = "unknown"
                base_pc = 0
            #
            line = "[0x%08X(%s) 0x%08X(%s)]\n"%(addr-base_read, name_read, pc-base_pc, name_pc)
            f.write(line)
        #
        
    #
#