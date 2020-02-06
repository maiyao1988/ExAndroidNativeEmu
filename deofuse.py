import sys
import os.path
import capstone
import keystone
from androidemu.utils import cfg
from androidemu.utils import tracer
import shutil

g_md_thumb = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
g_md_thumb.detail = True
g_md_arm = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
g_md_arm.detail = True

def get_jmp_dest(i):
    if (i.mnemonic[0] == 'b'):
        if (i.op_str[0] == '#'):
            jmp_addr = int(i.op_str[1:], 16)
            return jmp_addr
        #
    #
    return None
#

def get_block_codes(f, block, md):
    codelist = []
    b=block
    size = b.end - b.start
    f.seek(b.start, 0)
    code_bytes = f.read(size)
    codes = md.disasm(code_bytes, b.start)
    for c in codes:
        codelist.append(c)
    #
    return codelist
#

def find_main_control_block(f, blocks, base_addr, md):
    for b in blocks:
        #print(b)
        #print (b.parent)
        #查找主控制块
        #实测主控控制块的父亲节点不可能少于4个
        if (len(b.parent) > 4):
            codelist = get_block_codes(f, b, md)
            #一般主控制块的指令数量少于6个（不完全确定）,且多于一个指令
            n = len(codelist)
            if (n < 2):
                continue
            #
            # 这个数量可能需要调整，
            if (n < 6):
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
    #print ("main_block:%r"%main_cb)

    for b in blocks:
        #print(b)
        if (b == main_cb):
            continue
        #
        codelist = get_block_codes(f, b, md)
        
        n = len(codelist)

        if (n < 2):
        #只有一条指令而且跳回给自己的是死块
            if (n == 1):
                jmp_addr = get_jmp_dest(codelist[0])
                if (jmp_addr == None):
                    continue
                #
                if (jmp_addr == b.start):
                    dead_cb.append(b)    
                #
            #
            continue
        #
        if (n < 6):
            code_last = codelist[n-1]
            code_cmp = codelist[n-2]
            
            maybe_cb = False
            if (code_last.mnemonic[0] == "b"):
                #如果bxx跟着cmp，则疑似
                for j in range(n-1):
                    if (codelist[j].mnemonic == "cmp"):
                        maybe_cb = True
                        break
                    #
                #
            #
            if (maybe_cb):
                #再搜索一次，如果没有出现内存操作，则确认是
                for j in range(n-1):
                    mne = codelist[j].mnemonic
                    if (not mne.startswith("ldr") and not mne.startswith("str")):
                        obfuses_cb.append(b)
                        break
                    #
                #
            #
        #

    #
    return obfuses_cb, dead_cb
#

#将所有逻辑块最后的跳转，patch到另外一个有意义的逻辑块上
#而不是去到控制块上再分发。简化逻辑，需要依赖unicorn做虚拟执行找到下一个真实逻辑块
def patch_logical_blocks(fin, fout, logic_blocks, obfuses_blocks, trace, md):
    addr2ofb = {}
    for ofb in obfuses_blocks:
        addr2ofb[ofb.start] = ofb
    #
    for lb in logic_blocks:
        codelist = get_block_codes(fin, lb, md)
        n = len(codelist)
        code_last = codelist[n-1]

        #TODO:识别所有类型的跳转,现在只支持bxx导致的跳转
        mne = code_last.mnemonic
        if (mne[0] == "b" and mne not in ("blx", "bl")):
            #逻辑块结尾是否还会出现bne这些条件判断？待观察
            assert(mne == "b" or mne == "b.w")
            #主动跳转，结尾为跳转指令
            #print(lb)
            jmp_addr = get_jmp_dest(code_last)
            assert(jmp_addr != None)
            if (jmp_addr in addr2ofb):
                #跳转到控制块的，说明要修正到真实块
                print ("logic block with b %r should fix 0x%08X"%(lb, code_last.address))
                nexts = trace.get_next_trace_addr(code_last.address)
                print("nexts for 0x%08X [%s]"%(code_last.address, nexts))
            #
        #
        elif(lb.end in addr2ofb):
            #如果结尾就是控制块的开始，也需要patch
            print ("logic block %r should fix 0x%08X"%(lb, code_last.address))
        #
    #
#

def list_remove(srclist, listrmove):
    for item in listrmove:
        if (item in srclist):
            srclist.remove(item)
        #
    #
#

#尽量去除控制流平坦化fla
if __name__ == "__main__":
    if (len(sys.argv)<7):
        print("usage %s <elf_path> <elf_out_path> <trace_path> <func_start_hex> <end_start_hex> <is_thumb>"%(sys.argv[0]))
        sys.exit(-1)
    #
    path = sys.argv[1]
    out_path = sys.argv[2]
    trace_path = sys.argv[3]
    base_addr = int(sys.argv[4], 16)
    end_addr = int(sys.argv[5], 16)
    is_thumb = sys.argv[6] != "0"

    lib_name = os.path.basename(path)

    shutil.copyfile(path, out_path)
    with open(path, "rb") as f:
        blocks = cfg.create_cfg(f, base_addr, end_addr - base_addr, is_thumb)
        #print (blocks)
        if (is_thumb):
            md = g_md_thumb
        else:
            md = g_md_arm
        #
        of_b, dead_cb = find_ofuse_control_block(f, blocks, base_addr, md)

        #print("cbs:%r"%of_b)
        #print ("dead_cb:%r"%dead_cb)

        logic_blocks = list(blocks)

        list_remove(logic_blocks, of_b)
        list_remove(logic_blocks, dead_cb)
        
        #print (blocks)

        #print ("logic_block:%r"%logic_blocks)

        t = tracer.Tracer(trace_path, lib_name, base_addr, end_addr, logic_blocks)
        with open(out_path, "rb+") as fo:
            codelist = patch_logical_blocks(f, fo, logic_blocks, of_b , t, md)
        #
    #
#