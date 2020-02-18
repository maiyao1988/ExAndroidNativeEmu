import os
import capstone
import sys
from deofuse.intruction_mgr import IntructionManger
from deofuse.ins_helper import *

class CodeBlock:

    def __init__(self, start=0, end=0):
        self.start = start
        self.end = end
        self.parent = set()
        self.childs = set()
    #

    def __repr__(self):
        return "CodeBlock(0x%08X, 0x%08X)"%(self.start, self.end)
    #

    def __lt__(self, others):
        return self.start < others.start
    #
    
#

#判断是否无条件跳转
def is_jmp(i, base_addr, size):
    mne = i.mnemonic
    #b xxxx
    #mov pc, xxx
    #pop xxx, pc,xxx
    
    if mne[0] == "b" and mne not in ("bl", "blx", "bic", "bics"):
        return True
    #

    elif (mne.startswith("pop") or mne.startswith("ldm")):
        if (i.op_str.find("pc") > -1):
            return True
    elif (mne.startswith("mov")):
        if (i.op_str.split()[0].strip() == "pc"):
            return True
        #
    #

    if (mne in ("bl", "blx")):
        dest = get_jmp_dest(i)
        #这是一种反对抗行为，有些混淆会用bl作为跳转，如果bl跳转目标为本函数范围，依然认为是个普通跳转，而不是一个函数调用
        if (dest != None and dest >= base_addr and dest < base_addr+size):
            return True
        #
    #
    return False
#

#create cfg like ida
def create_cfg(f, base_addr, size, thumb):
    #thumb is same as IDA Atl+G
    ins_mgr = IntructionManger(thumb)
    block_starts_map = {}
    blocks = []
    f.seek(base_addr, 0)
    code_bytes = f.read(size)
    codes = ins_mgr.disasm(code_bytes, base_addr)
    m = 0
    
    cb = CodeBlock()
    cb.start = base_addr
    block_starts_map[base_addr] = cb
    blocks.append(cb)
    block_back_jump = set()
    cb_now = None
    #print (hex(base_addr))
    for i in codes:
        addr = i.address
        
        instruction_str = ''.join('{:02X} '.format(x) for x in i.bytes)
        if (addr in block_starts_map):
            if (cb_now != None):
                cb_now.end = addr
            #
            cb_now = block_starts_map[addr]
        #

        mne = i.mnemonic
        addr_next = addr + i.size

        line = "[%16s]0x%08X:\t%s\t%s"%(instruction_str, addr, i.mnemonic.upper(), i.op_str.upper())
        #print (line)
        if (is_jmp(i, base_addr, size)):
            if (mne[0] == "b"):
                #print("in")
                op = i.op_str.strip()
                #跳转指令，需要
                if (op[0] == "#"):
                    cb_now.end = addr
                    child_start = int(op[1:], 16)
                    #print ("target_block 0x%08X"%child_start)
                    target_block = None
                    if (child_start not in block_starts_map):
                        #print ("hhh %08X"%child_start)
                        target_block = CodeBlock()
                        target_block.start = child_start
                        block_starts_map[child_start] = target_block
                        blocks.append(target_block)
                        if (child_start < addr):
                            #print ("back jump 0x%08X to 0x%08X"%(addr, child_start))
                            block_back_jump.add(target_block)
                        #
                    #
                    else:
                        target_block = block_starts_map[child_start]
                    #

                    #print ("cb_now %r child %r"%(cb_now, target_block))
                    cb_now.childs.add(target_block)
                    #print(cb_now.childs)
                    target_block.parent.add(cb_now)
                #
            #
            #print (mne + " " + i.op_str)
            if (addr_next < base_addr + size):
                if (addr_next not in block_starts_map):
                    next_block = CodeBlock()
                    next_block.start = addr_next
                    block_starts_map[next_block.start] = next_block
                    blocks.append(next_block)
                #
            #
        #
        #print (hex(addr_next))
        if (addr_next in block_starts_map):
            #print ("cb_now %r child %r"%(cb_now, next_block))
            #pop xxx, pc mov pc, xxx and so on
            if not is_jmp(i, base_addr, size):
                next_block = block_starts_map[addr_next]
                next_block.parent.add(cb_now)
                cb_now.childs.add(next_block)
            #
        #
        if (i.size + addr >= base_addr + size):
            cb_now.end = i.size+addr
        #
    #
    blocks.sort()

    #修复因为有往回跳的指令而出现的block overlap问题
    for bjb in block_back_jump:
        print ("fix bjb:%r"%bjb)
        for b in blocks:
            if bjb == b:
                continue
            elif(b.start < bjb.start and b.end > bjb.start):
                assert(bjb.end == 0)

                bjb.end = b.end
                b.end = bjb.start
                bjb.childs.update(b.childs)
                b.childs.clear()
                b.childs.add(bjb)
                bjb.parent.add(b)

                print ("-new bjb:%r"%bjb)
                break
            #
        #
    #
    return blocks
#

if (__name__ == "__main__"):
    path = sys.argv[1]
    base_addr = int(sys.argv[2], 16)
    end_addr = int(sys.argv[3], 16)
    with  open(path, "rb") as f:
        c = create_cfg(f, base_addr, end_addr - base_addr, 1)
        print(c)
        print (c[12].parent)
    #
#