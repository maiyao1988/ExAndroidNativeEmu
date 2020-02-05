import sys
import capstone
import keystone
from androidemu.utils import cfg

g_md_thumb = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
g_md_thumb.detail = True
g_md_arm = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
g_md_arm.detail = True

def find_main_control_block(f, blocks, base_addr, md):
    for b in blocks:
        #print(b)
        #print (b.parent)
        #查找主控制块
        #实测主控控制块的父亲节点不可能少于4个
        if (len(b.parent) > 4):
            codelist = []
            size = b.end - b.start
            f.seek(b.start, 0)
            code_bytes = f.read(size)
            codes = md.disasm(code_bytes, base_addr)
            for c in codes:
                codelist.append(c)
            #
            #一般主控制块的指令数量少于三个（不完全确定）,且多于一个指令
            n = len(codelist)
            if (n < 2):
                continue
            #
            if (n < 4):
                code_last = codelist[n-1]
                code_cmp = codelist[n-2]
                if (code_last.mnemonic[0] == "b" and code_cmp.mnemonic=="cmp"):
                    return b
                #
            #
        #
    #
#

def find_ofuse_control_block(f, blocks, base_addr, md):
    obfuses_cb = []
    dead_cb = []
    main_cb = find_main_control_block(f, blocks, base_addr, md)
    assert(main_cb != None)
    obfuses_cb.append(main_cb)
    print ("main_block:%r"%main_cb)

    for b in blocks:
        #print(b)
        if (b == main_cb):
            continue
        #
        size = b.end - b.start
        f.seek(b.start, 0)
        code_bytes = f.read(size)
        codes = md.disasm(code_bytes, b.start)
        codelist = []
        for i in codes:
            instruction_str = ''.join('{:02X} '.format(x) for x in i.bytes)
            line = "[%16s]0x%08X:\t%s\t%s"%(instruction_str, i.address, i.mnemonic.upper(), i.op_str.upper())
            #print (line)
            codelist.append(i)
        #
        n = len(codelist)

        if (n < 2):
        #只有一条指令而且跳回给自己的是死块
            if (n == 1):
                if (codelist[0].mnemonic == 'b'):
                    if (codelist[0].op_str[0] == '#'):
                        jmp_addr = int(codelist[0].op_str[1:], 16)
                        #print ("0x%x"%jmp_addr)
                        if (jmp_addr == b.start):
                            dead_cb.append(b)
                        #
                    #
            #
            continue
        #
        if (n < 5):
            code_last = codelist[n-1]
            code_cmp = codelist[n-2]
            
            if (code_last.mnemonic[0] == "b"):
                for j in range(n-1):
                    if (codelist[j].mnemonic == "cmp"):
                        obfuses_cb.append(b)
                        break
                    #
                #
            #
        #

    #
    return obfuses_cb, dead_cb
#

#尽量去除控制流平坦化fla
if __name__ == "__main__":
    if (len(sys.argv)<5):
        print("usage %s <elf_path> <elf_out_path> <func_start_hex> <end_start_hex> <is_thumb>"%(sys.argv[0]))
        sys.exit(-1)
    #
    path = sys.argv[1]
    out_path = sys.argv[2]
    base_addr = int(sys.argv[3], 16)
    end_addr = int(sys.argv[4], 16)
    is_thumb = sys.argv[5] != "0"
    with  open(path, "rb") as f:
        blocks = cfg.create_cfg(f, base_addr, end_addr - base_addr, is_thumb)
        #print (blocks)
        if (is_thumb):
            md = g_md_thumb
        else:
            md = g_md_arm
        #
        of_b, dead_cb = find_ofuse_control_block(f, blocks, base_addr, md)
        print("cbs:%r"%of_b)
        print ("dead_cb:%r"%dead_cb)
    #
#