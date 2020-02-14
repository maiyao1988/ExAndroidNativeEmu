import sys
import os.path
from deofuse.intruction_mgr import IntructionManger
from deofuse.ins_helper import *
from deofuse import cfg
from deofuse import tracer
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

def find_main_control_block(f, blocks, base_addr, ins_mgr):
    for b in blocks:
        #print(b)
        #print (b.parent)
        #查找主控制块
        #实测主控控制块的父亲节点不可能少于4个
        if (len(b.parent) > 4):
            codelist = get_block_codes(f, b, ins_mgr)
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

def find_ofuse_control_block(f, blocks, base_addr, ins_mgr):
    obfuses_cb = []
    dead_cb = []
    main_cb = find_main_control_block(f, blocks, base_addr, ins_mgr)
    assert(main_cb != None)
    obfuses_cb.append(main_cb)
    #print ("main_block:%r"%main_cb)

    for b in blocks:
        #print(b)
        if (b == main_cb):
            continue
        #
        codelist = get_block_codes(f, b, ins_mgr)
        
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
                    #很短的而且有比较的都疑似控制块
                    if (codelist[j].mnemonic == "cmp"):
                        maybe_cb = True
                        break
                    #
                    elif (codelist[j].mnemonic.startswith("it")):
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
        clean_bytes(fo, ob.start, ob.end)
    #
#

#将所有逻辑块最后的跳转，patch到另外一个有意义的逻辑块上
#而不是去到控制块上再分发。简化逻辑，需要依赖unicorn做虚拟执行找到下一个真实逻辑块
def patch_logical_blocks(fin, fout, logic_blocks, obfuses_blocks, trace, ins_mgr):
    addr2ofb = {}
    for ofb in obfuses_blocks:
        addr2ofb[ofb.start] = ofb
    #
    #print ("logic_blocks:%r"%logic_blocks)
    for lb in logic_blocks:
        codelist = get_block_codes(fin, lb, ins_mgr)
        n = len(codelist)
        code_last = codelist[n-1]

        #TODO:识别所有类型的跳转,现在只支持bxx导致的跳转
        mne = code_last.mnemonic
        no_run_blocks = []

        indexes = trace.get_trace_index(lb.start)
        if (len(indexes) < 1):
            #如果入口没有执行过，说明这个块肯定没有执行过，跳过处理
            print("warning true block %r has not run in unicorn"%lb)
            no_run_blocks.append(lb)
            continue
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

                n_next = len(nexts)
                #暂时没见过超过两个的目的地
                assert(n_next < 3)
                nexts_list = list(nexts)
                if (n_next == 0):
                    print("warning true block %r has no sub true block"%lb)
                elif (n_next == 1):
                    #改跳转地址到下一个真实块

                    code_r = "%s %s"%(code_last.mnemonic, code_last.op_str)

                    fix_code = "b #0x%X"%(nexts_list[0],)

                    addr_next_insn = write_codes(fo, code_last.address, [fix_code], ins_mgr)
                    assert addr_next_insn <= lb.end, "patch %s address :0x%08X to %s error size not enouth"%(code_r, code_last.address, fix_code)

                    clean_bytes(fo, addr_next_insn, lb.end)
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
                        #print (addr,nexts)
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
                    
                    '''itt 指令指令一般都是这种情况
                    itt ne
                    movt xxxxx
                    movw xxxxx
                    直接替换成
                    nop
                    bne xxxx
                    b xxx
                    nop
                    '''
                    addr_next_insn = write_codes(fo, itt_code.address, [fixed_str1, fixed_str2], ins_mgr)
                    clean_bytes(fo, addr_next_insn, lb.end)
                #
            #
        #
        elif(lb.end in addr2ofb):
            print ("logic block normal %r"%(lb, ))
            #如果结尾就是控制块的开始，也需要patch
            code_to_patch = None
            for index in range(n-1, -1, -1):
                code_to_patch = codelist[index]
                ids = trace.get_trace_index(code_to_patch.address)
                #找到该块最后一个有执行的指令，patch。
                if len(ids)<=0:
                    print("warning find block end in obfuse block code in block 0x%08X not find in trace"%code_to_patch.address)
                else:
                    break
            #
            #patch最后一条执行的指令
            assert(len(ids)>0)
            next_id = ids[0] + 1
            next_addr = trace.get_trace_by_index(next_id)
            print("address 0x%08X is the last run code in block %r next [0x%08X]"%(code_to_patch.address, lb, next_addr))
            
            code_r = "%s %s"%(code_to_patch.mnemonic, code_to_patch.op_str)

            fix_code = "b 0x%x"%(next_addr, )

            addr_next_insn = write_codes(fo, code_to_patch.address, [fix_code], ins_mgr)
            assert addr_next_insn <= lb.end, "patch %s address :0x%08X to %s error size not enouth"%(code_r, code_last.address, fix_code)

            clean_bytes(fo, addr_next_insn, lb.end)
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
        ins_mgr = IntructionManger(is_thumb)

        of_b, dead_cb = find_ofuse_control_block(f, blocks, base_addr, ins_mgr)

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
            codelist = patch_logical_blocks(f, fo, logic_blocks, of_b , t, ins_mgr)
        #
    #
#