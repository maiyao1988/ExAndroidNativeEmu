import os
import capstone
import keystone
import sys


g_md_thumb = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
g_md_thumb.detail = True
g_md_arm = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
g_md_arm.detail = True

def hex2sign_int(hex_str):
    intval = int(hex_str, 16)
    if intval >= 0x7FFFFFFF:
        intval -= 0xFFFFFFFF
        intval -= 1
    #
    return intval
#

class CodeBlock:

    def __init__(self):
        self.start = 0
        self.end = 0
        self.parent = set()
        self.childrend = set()
    #

    def __repr__(self):
        return "CodeBlock 0x%08X-0x%08X"%(self.start, self.end)
    #

    def __lt__(self, others):
        return self.start < others.start
    #
#


#create cfg like ida
def create_cfg(f, base_addr, size, thumb):
    #thumb is same as IDA Atl+G
    md = None
    if (thumb):
        md = g_md_thumb
    #
    else:
        md = g_md_arm
    #
    block_starts_map = {}
    blocks = []
    f.seek(base_addr, 0)
    code_bytes = f.read(size)
    codes = md.disasm(code_bytes, base_addr)
    m = 0
    
    cb = CodeBlock()
    cb.start = base_addr
    block_starts_map[base_addr] = cb
    blocks.append(cb)
    block_back_jump = set()
    cb_now = None
    print (hex(base_addr))
    for i in codes:
        addr = i.address
        
        instruction_str = ''.join('{:02X} '.format(x) for x in i.bytes)
        #line = "[%16s]0x%08X:\t%s\t%s"%(instruction_str, addr, i.mnemonic.upper(), i.op_str.upper())
        #print (line)
        if (addr in block_starts_map):
            if (cb_now != None):
                cb_now.end = addr
            #
            cb_now = block_starts_map[addr]
        #

        mne = i.mnemonic
        addr_next = addr + i.size
        if (mne[0] == "b" and mne not in ("bl", "blx")):
            op = i.op_str.strip()
            if (op[0] == "#"):
                cb_now.end = addr
                child_start = int(op[1:], 16)
                target_block = None
                if (child_start not in block_starts_map):
                    #print ("hhh %08X"%child_start)
                    target_block = CodeBlock()
                    target_block.start = child_start
                    block_starts_map[child_start] = target_block
                    blocks.append(target_block)
                    if (child_start < addr):
                        block_back_jump.add(target_block)
                    #
                #
                else:
                    target_block = block_starts_map[child_start]
                #

                #print ("cb_now %r child %r"%(cb_now, target_block))
                cb_now.childrend.add(target_block)
                #print(cb_now.childrend)
                target_block.parent.add(cb_now)

                print (addr_next)
                if (addr_next < base_addr + size):
                    if (addr_next not in block_starts_map):
                        next_block = CodeBlock()
                        next_block.start = addr_next
                        block_starts_map[next_block.start] = next_block
                        blocks.append(next_block)
                    #
                #
                #print (next_block)
            #
        #
        if (addr_next in block_starts_map):
            if mne != "b":
                #print ("cb_now %r child %r"%(cb_now, next_block))
                next_block = block_starts_map[addr_next]
                next_block.parent.add(cb_now)
                cb_now.childrend.add(next_block)
            #
        #
        if (i.size + addr >= base_addr + size):
            cb_now.end = i.size+addr
        #
    #
    blocks.sort()

    for bjb in block_back_jump:
        print ("fix bjb:%r"%bjb)
        for b in blocks:
            if bjb == b:
                continue
            elif(b.start < bjb.start and b.end > bjb.start):
                assert(bjb.end == 0)

                bjb.end = b.end
                b.end = bjb.start
                bjb.childrend.update(b.childrend)
                b.childrend.clear()
                b.childrend.add(bjb)
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