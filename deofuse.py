import sys
import os.path
import capstone
import keystone
from androidemu.utils import cfg
from androidemu.utils import tracer
import shutil

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
    assert size > 0, "block %r size <=0"%b
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

def clear_control_block(fo, obfuses_blocks):
    
    for ob in obfuses_blocks:
        sz = ob.end - ob.start
        print ("clear %r"%(ob, ))
        fo.seek(ob.start, 0)
        for _ in range(0, sz):
            b = bytearray([0])
            #print(len(b))
            fo.write(b)
        #
    #
    
#

#将所有逻辑块最后的跳转，patch到另外一个有意义的逻辑块上
#而不是去到控制块上再分发。简化逻辑，需要依赖unicorn做虚拟执行找到下一个真实逻辑块
def patch_logical_blocks(fin, fout, logic_blocks, obfuses_blocks, trace, md, ks):
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
        no_run_blocks = []
        if (mne[0] == "b" and mne not in ("blx", "bl")):
            #逻辑块结尾是否还会出现bne这些条件判断？待观察
            assert(mne == "b" or mne == "b.w")
            #主动跳转，结尾为跳转指令
            #print(lb)
            jmp_addr = get_jmp_dest(code_last)
            assert(jmp_addr != None)
            if (jmp_addr in addr2ofb):
                #跳转到控制块的，说明要修正到真实块
                #print ("logic block with b %r should fix 0x%08X"%(lb, code_last.address))
                nexts = trace.get_trace_next(code_last.address)
                if (nexts == None):
                    #没有后续原因是后续block没有跑过，暂时不处理
                    print("warning true block %r has no sub true block, maybe path not run in unicorn"%lb)
                    no_run_blocks.append(lb)
                #
                else:
                    n_next = len(nexts)
                    #暂时没见过超过两个的目的地
                    assert(n_next < 3)
                    nexts_list = list(nexts)
                    if (n_next == 0):
                        print("warning true block %r has no sub true block"%lb)
                    elif (n_next == 1):
                        #只有一个目的地
                        op = mne
                        #改跳转地址到下一个真实块

                        code = "%s #0x%X"%(op, nexts_list[0])

                        #print("nexts for 0x%08X [%s]"%(code_last.address, nexts))

                        #print("cs code (%s) %r addr %x"%(code, list(code_last.bytes), code_last.address))
                        code_r = "%s %s"%(code_last.mnemonic, code_last.op_str)
                        r, count = ks.asm(code, code_last.address)

                        assert code_last.size >= len(r), "patch %s address :0x%08Xto %s error size not enouth"%(code_r, code_last.address, code)
                        print("[%r] fix code from (%s) [%r] to (%s) [%r]"%(lb, code_r, list(code_last.bytes), code, r))

                        fo.seek(code_last.address, 0)
                        fo.write(bytearray(r))
                    #
                    elif (n_next == 2):
                        #TODO:两个目的地，需要根据是否跑过一些指令判断，修正跳转
                        print ("%r has two destination %r"%(lb, nexts))
                        assert(n > 1)
                        itt_code = None
                        trace_start=-1
                        itt_mne = ""
                        #从最后找到第一个条件语句
                        for id in range(n-2, -1, -1):
                            code = codelist[id]
                            mne = code.mnemonic
                            if (mne.startswith("it")):
                                #找到itt之后的语句，然后一步步trace下来
                                trace_start = id+1
                                itt_code = code
                                break
                            #
                        #
                        fix_to_addr1 = -1
                        assert(trace_start >= 0)
                        code_run_if = codelist[trace_start]
                        #从itt下一条指令开始跟踪，根据跟踪到的情况确定跳转过去的条件
                        id_if = trace.get_trace_index(code_run_if.address)
                        trace_id = id_if[0]
                        while True:
                            trace_id = trace_id + 1
                            addr = trace.get_trace_by_index(trace_id)
                            print (addr,nexts)
                            if (addr in nexts):
                                fix_to_addr1 = addr
                                break
                            #
                        #

                        assert(fix_to_addr1 > 0)
                        nexts_list.remove(fix_to_addr1)
                        fix_to_addr2 = nexts_list[0]
                        
                        fixed_str1 = "b%s #0x%X"%(itt_code.op_str, fix_to_addr1)

                        fixed_str2 = "b #0x%X"%(fix_to_addr2,)

                        code_r1 = "%s %s"%(itt_code.mnemonic, itt_code.op_str)
                        code_r2 = "%s %s"%(code_run_if.mnemonic, code_run_if.op_str)
                        
                        b1 = ks.asm(fixed_str1, itt_code.address)[0]
                        b2 = ks.asm(fixed_str2, code_run_if.address)[0]

                        assert itt_code.size >= len(b1), "patch %s address :0x%08Xto %s error size not enouth"%(code_r1, itt_code.address, fixed_str1)
                        assert code_run_if.size >= len(b2), "patch %s address :0x%08Xto %s error size not enouth"%(code_r2, code_run_if.address, fixed_str2)

                        print("[%r] two fix code from (%s) [%r] to (%s) [%r]"%(lb, code_r1, list(itt_code.bytes), fixed_str1, b1))
                        print("[%r] two fix code from (%s) [%r] to (%s) [%r]"%(lb, code_r2, list(code_run_if.bytes), fixed_str2, b2))

                        fo.seek(itt_code.address)
                        fo.write(bytearray(b1))
                        fo.write(bytearray(b2))

                        nleft = lb.end - (itt_code.address+ len(b1) + len(b2))
                        print ("n left %d"%nleft)
                        for _ in range(0, nleft):
                            b = bytearray([0])
                            fo.write(b)
                        #
                    #
                #
            #
        #
        elif(lb.end in addr2ofb):
            #如果结尾就是控制块的开始，也需要patch
            print ("logic block normal %r should fix 0x%08X"%(lb, code_last.address))
            ids = trace.get_trace_index(code_last.address)
            next_id = ids[0] + 1
            next_addr = trace.get_trace_by_index(next_id)
            print("0x%08X next [0x%08X]"%(code_last.address, next_addr))
            
            fix_code = "b 0x%x"%(next_addr, )
            b = ks.asm(fix_code, code_last.address)[0]

            code_r = "%s %s"%(code_last.mnemonic, code_last.op_str)
            n_len = len(b)
            assert code_last.size >= n_len, "patch %s address :0x%08Xto %s error size not enouth"%(code_r, code_last.address, fix_code)
            print("[%r] normal fix code from (%s) [%r] to (%s) [%r]"%(lb, code_r, list(code_last.bytes), fix_code, b))
            #直接patch结尾指令
            fo.seek(code_last.address)
            fo.write(bytearray(b))
            nleft = lb.end - (code_last.address + n_len)
            for _ in range(0, nleft):
                b = bytearray([0])
                fo.write(b)
            #
        #
    #
    clear_control_block(fo, obfuses_blocks)
    #clear_control_block(fo, no_run_blocks)
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
        md = None
        ks = None
        if (is_thumb):
            md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
            ks = keystone.Ks(keystone.KS_ARCH_ARM, keystone.KS_MODE_THUMB)
        else:
            md = g_md_arm = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
            ks = keystone.Ks(keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM) 
        #

        md.detail = True
        of_b, dead_cb = find_ofuse_control_block(f, blocks, base_addr, md)

        #print("cbs:%r"%of_b)
        #print ("dead_cb:%r"%dead_cb)

        logic_blocks = list(blocks)

        list_remove(logic_blocks, of_b)
        list_remove(logic_blocks, dead_cb)
        
        #print(logic_blocks)
        #print (blocks)

        #print ("logic_block:%r"%logic_blocks)

        t = tracer.Tracer(trace_path, lib_name, base_addr, end_addr, logic_blocks)
        with open(out_path, "rb+") as fo:
            codelist = patch_logical_blocks(f, fo, logic_blocks, of_b , t, md, ks)
        #
    #
#