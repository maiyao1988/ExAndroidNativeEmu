import os

_cond_oposite_map = {"eq":"ne", "cs":"cc", "mi":"pl", "vs":"vc", "hi":"ls", "ge":"lt", "gt":"le", "ne":"eq", "cc":"cs", "pl":"mi", "vc":"vs", "ls":"hi", "lt":"ge", "le":"ge"}

_b_cond_ins = ["b"+cond for cond in _cond_oposite_map]

def is_jmp_condition(ins):
    global _b_cond_ins
    return ins.mnemonic in _b_cond_ins
#

def is_jmp_condition_str(ins_str):
    global _b_cond_ins
    ins_str_sa = ins_str.lower().split()
    return ins_str_sa[0] in _b_cond_ins
#

def is_jmp_insn(ins):
    mne = ins.mnemonic
    return mne[0] == "b" and mne not in ("blx", "bl", "bic", "bics") or mne in ("cbz", "cbnz")
#

def condi_oposite(cond):
    return _cond_oposite_map(cond)
#

def write_codes(f, address, max_size, insns, ins_mgr):
    f.seek(address, 0)
    next_addr = address
    byte_list = []
    size_left = max_size
    for code_str in insns:
        b = ins_mgr.asm(code_str, next_addr)[0]
        byte_list.extend(b)
        next_addr = next_addr + len(b)
        size_left = size_left - len(b)
        if (size_left < 0):
            #空间不足，报错
            #print("not enough size")
            return -1
        #
        #print("patch 0x%08X to %s[%r]"%(next_addr, code_str, [hex(x) for x in b]))
    #
    f.write(bytearray(byte_list))
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