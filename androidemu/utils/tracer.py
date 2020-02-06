import os
import sys

class TraceInfo:

    def __init__(self, addr):
        self.addr = addr
        self.next = set()
    #

    def __repr__(self):
        return "TraceInfo(0x%08X)"%(self.addr,)
    #

    def __lt__(self, others):
        return self.addr < others.addr
    #
#

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
        self.__addr2trace = {}

        with open(trace_path, "r") as f:
            prev_trace_info = None
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
                prev_trace_info = trace_info
            #
        #
        #print(self.__addr2trace)
    #


    #获取一条指令执行之后，可能执行的下一条指令地址，可能有多条
    def get_next_trace_addr(self, addr):
        if (addr in self.__addr2trace):
            addr = self.__addr2trace[addr].next
            return addr
        #
        return None
    #
#