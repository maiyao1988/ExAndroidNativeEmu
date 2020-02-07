import os
import sys

#标识指令运行的运行信息
class Tracer:

    def __addr_in_blocks(self, addr, blocks):
        for b in blocks:
            if (b.start <= addr and b.end > addr):
                return True
            #
        #
        return False
    #

    def __init__(self, trace_path, lib_name, start_addr, end_addr, blocks_to_trace):
        self.__lib_name = lib_name
        self.__start_addr = start_addr
        self.__end_addr = end_addr

        self.__trace_list = []

        with open(trace_path, "r") as f:
            for line in f:
                line = line.strip()
                if (line.find(lib_name)<0):
                    continue
                #
                sa = line.split(":")
                start = sa[0].rfind("]")+1
                addr = int(sa[0][start:], 16)
                
                if (addr < start_addr or addr >= end_addr):
                    continue
                #
                #print("%x %r"%(addr, blocks_to_trace))
                if (not self.__addr_in_blocks(addr, blocks_to_trace)):
                    continue
                #

                self.__trace_list.append(addr)
                '''
                trace_info = None
                if (addr not in self.__addr2trace):
                    trace_info = TraceInfo(addr)
                    self.__addr2trace[addr] = trace_info
                #
                else:
                    trace_info = self.__addr2trace[addr]
                #
                if (prev_trace_info == None):
                    prev_trace_info = trace_info
                    continue
                #
                prev_trace_info.next.add(addr)
                trace_info.prev.add(prev_trace_info.addr)
                prev_trace_info = trace_info
                '''
            #
        #
        #print(self.__addr2trace)
    #

    def get_trace_index(self, addr):
        out = []
        l = len(self.__trace_list)
        for i in range(0, l):
            if (addr == self.__trace_list[i]):
                out.append(i)
            #
        #
        return out
    #

    def get_trace_by_index(self, index):
        l = len(self.__trace_list)
        if (index >= l):
            return None
        return self.__trace_list[index]
    #

    def get_trace_next(self, addr):
        next_addrs = set()
        indexs = self.get_trace_index(addr)
        for i in indexs:
            addr = self.get_trace_by_index(i+1)
            if (addr != None):
                next_addrs.add(addr)
        #
        return next_addrs
    #

#