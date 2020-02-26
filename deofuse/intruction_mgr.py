import os
import sys
import capstone
import keystone
from deofuse.ins_helper import *

class IntructionManger:
    
    def __init__(self, is_thumb):
        self.__is_thumb = is_thumb
        if (is_thumb):
            self.__cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
            self.__ks = keystone.Ks(keystone.KS_ARCH_ARM, keystone.KS_MODE_THUMB)
        else:
            self.__cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
            self.__ks = keystone.Ks(keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM)
        #
    #

    def asm(self, ins_str, offset):
        if (self.__is_thumb):
            sa = ins_str.split(" ")
            if (len(sa) > 1):
                if (ins_str[0] == "b" and not ins_str.startswith("bic")):
                    op_type = sa[0]
                    op = sa[1]
                    if (op[0] == "#"):
                        op = op[1:]
                    #
                    if (op.startswith("0x")):
                        imm = int(op, 16)
                        rel = imm - offset
                        if (op_type == "b"):
                            if (rel < -2048 or rel >= 2048):
                                #这个是ksstone的bug，总是相当于rel-4
                                ins_str = "%s #%s"%(sa[0], hex(rel-4))
                                offset = 0
                        else:
                            if (rel < -256 or rel >= 256):
                                ins_str = "%s #%s"%(sa[0], hex(rel-4))
                                offset = 0
                        #由于keystone的thumb2指令相对地址计算有bug，
                        #当指令是b.w，bne.w等w跳转指令会直接忽略offset参数
                        #所以这类指令我们不使用offset参数，自己计算偏移
                    #
                #
            #
        #
        return self.__ks.asm(ins_str, offset)
    #


    #递归下降返汇编代码，为了剔除非代码的部分
    def __disasm_recur(self, codelist, code_addr_set, base_addr, code_bytes, dis_addr):
        #print ("__disasm_recur dis addr 0x%08X"%(dis_addr,))
        if (dis_addr in code_addr_set):
            return
        #
        len_cbs = len(code_bytes)
        if (dis_addr < base_addr):
            return
        #
        my_code_bytes_off = dis_addr - base_addr
        if (my_code_bytes_off >= len_cbs):
            return
        #
        my_code_bytes = code_bytes[my_code_bytes_off:]
        codes = self.__cs.disasm(my_code_bytes, dis_addr)
        code_prev = [None, None]

        for c in codes:
            
            if (c.address in code_addr_set):
                break
            else:
                #assert c.address not in code_addr_set, "0x%08X not evalute"%c.address
                code_addr_set.add(c.address)
                codelist.append(c)
                #print ("0x%08X %s %s"%(c.address, c.mnemonic.upper(), c.op_str.upper()))
                if (is_jmp(c, base_addr, len_cbs)):
                    #print ("get jmp %s %s 0x%08X"%(c.mnemonic, c.op_str, c.address))
                    if (is_table_jump(c)):
                        assert code_prev[0] != None and code_prev[1] != None, "tbb/tbh list range not found..."
                        code_cmp = code_prev[0]
                        assert code_cmp.mnemonic == "cmp", "tbb/tbh list range not found..."
                        op_str = code_cmp.op_str
                        imm_id=op_str.find("#")
                        ntable = int(op_str[imm_id+1:], 16)+1
                        itemsz = 2 #tbh
                        mne = c.mnemonic
                        if (mne.startswith("tbb")):
                            itemsz = 1
                        #
                        assert c.op_str.find("pc")>-1, "table jump not by pc is not support now"
                        addr = c.address
                        for jmp_id in range(0, ntable):
                            offset_in_byte = addr + c.size + jmp_id * itemsz - dis_addr
                            jmp_off_b = my_code_bytes[offset_in_byte:offset_in_byte+itemsz]
                            jmp_off = int.from_bytes(jmp_off_b, byteorder='little')
                            dest_addr = addr + 4 + jmp_off*2
                            self.__disasm_recur(codelist, code_addr_set, base_addr, code_bytes, dest_addr)
                        #
                        break
                    #
                    else:
                        #非表跳转，b, bne, cbz等
                        dest_addr = get_jmp_dest(c)
                        if (dest_addr == None):
                            print("can not get dest from ins %s %s addr 0x%08X"%(c.mnemonic, c.op_str, c.address))
                            if (is_jmp_no_ret(c)):
                                break
                            #
                        #
                        print ("call by jmp ins:%s %s addr: 0x%08X dest: 0x%08X"%(c.mnemonic, c.op_str, c.address, dest_addr))
                        self.__disasm_recur(codelist, code_addr_set, base_addr, code_bytes, dest_addr)
                        if (is_jmp_no_ret(c)):
                            break
                        #
                    #
                #
            #
        
            code_prev[0] = code_prev[1]
            code_prev[1] = c
        #
    #

    @staticmethod
    def _cmp(a1):
        return a1.address
    #

    #递归下降反汇编代码，为了剔除非代码的部分
    def disasm(self, code_bytes, start_addr):
        code_addr_set = set()
        codelist = []
        self.__disasm_recur(codelist, code_addr_set, start_addr, code_bytes, start_addr)
        new_list=sorted(codelist, key=IntructionManger._cmp)
        
        '''
        for ins in new_list:
            print("[0x%08X] %s %s"%(ins.address, ins.mnemonic.upper(), ins.op_str.upper()))
        #
        '''
        
        #print(len(new_list))

        #sys.exit(-1)
        return new_list
    #
#