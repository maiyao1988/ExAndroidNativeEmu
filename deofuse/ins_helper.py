import os

def write_codes(f, address, insns, ins_mgr):
    f.seek(address, 0)
    next_addr = address
    for code_str in insns:
        b1 = ins_mgr.asm(code_str, next_addr)[0]
        print("patch 0x%08X to %s[%r]"%(next_addr, code_str, [hex(x) for x in b1]))
        f.write(bytearray(b1))
        next_addr = next_addr + len(b1)
    #
    return next_addr
#

def clean_bytes(f, addr_from, addr_to):
    f.seek(addr_from, 0)
    nleft = addr_to - addr_from
    assert nleft>=0
    #print ("n left %d"%nleft)
    for _ in range(0, nleft):
        b = bytearray([0])
        f.write(b)
    #
#


def get_jmp_dest(i):
    if (i.mnemonic[0] == 'b'):
        if (i.op_str[0] == '#'):
            jmp_addr = int(i.op_str[1:], 16)
            return jmp_addr
        #
    #
    return None
#

def get_block_codes(f, block, ins_mgr):
    codelist = []
    b=block
    size = b.end - b.start
    assert size > 0, "block %r size <=0"%b
    f.seek(b.start, 0)
    code_bytes = f.read(size)
    codes = ins_mgr.disasm(code_bytes, b.start)
    for c in codes:
        codelist.append(c)
    #
    return codelist
#