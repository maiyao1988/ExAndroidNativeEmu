import os
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

    def __get_all_jump_dest(self, codelist, base_addr, code_bytes):
        base_addr=codelist[0].address
        dests = set()
        nlen = len(codelist)
        for index in range(0, nlen):
            code = codelist[index]
            mne = code.mnemonic
            if (is_jmp(code)):
                dest = get_jmp_dest(code)
                if (dest != None):
                    dests.add(dest)
                #
                else:
                    if (code.mnemonic in ("tbb", "tbh", "tbb.w", "tbh.w")):
                        assert index-2 > 0, "tbb/tbh list range not found..."
                        code_cmp = codelist[index-2]
                        assert code_cmp.mnemonic == "cmp", "tbb/tbh list range not found..."
                        op_str = code_cmp.op_str
                        imm_id=op_str.find("#")
                        ntable = int(op_str[imm_id+1:], 16)+1
                        itemsz = 2 #tbh
                        if (mne.startswith("tbb")):
                            itemsz = 1
                        #
                        assert code.op_str.find("pc")>-1, "table jump not by pc is not support now"
                        addr = code.address
                        for jmp_id in range(0, ntable):
                            offset_in_byte = addr + code.size + jmp_id * itemsz - base_addr
                            jmp_off_b = code_bytes[offset_in_byte:offset_in_byte+itemsz]
                            jmp_off = int.from_bytes(jmp_off_b, byteorder='little')
                            dest = addr + 4 + jmp_off*2
                            dests.add(dest)
                        #
                    #
                #
            
        #
        
        return dests
    #

    def __find_nearest_dest(self, address, dests):
        diff = 0xFFFFFFFF
        r = 0
        for d in dests:
            if (d > address):
                my_diff = d - address
                if (diff > my_diff):
                    diff = my_diff
                    r = d
                #
            #
        #
        return r
    #

    def disasm(self, code_bytes, start_addr, size):
        #this asm in ida can disasm..., true bytes return by kstool is [04 b0]
        #0001D60E 04 B8                       ADD             SP, SP, #0x10
        codelist = []
        dis_start = start_addr
        end_addr = start_addr + size
        all_dests = set()
        n_start = 0
        my_code_bytes = code_bytes
        while True:
            codes = self.__cs.disasm(my_code_bytes, dis_start)
            tmp_code_list = []
            for c in codes:
                tmp_code_list.append(c)
            #
            codelist.extend(tmp_code_list)
            nlen = len(tmp_code_list)
            last_code = tmp_code_list[nlen-1]
            code_end_addr = last_code.address + last_code.size
            if (end_addr == code_end_addr):
                break
            #
            dests = self.__get_all_jump_dest(tmp_code_list, start_addr, my_code_bytes)
            all_dests.update(dests)
            dis_start = self.__find_nearest_dest(last_code.address, all_dests)
            off = dis_start - start_addr
            my_code_bytes = code_bytes[dis_start-start_addr:]
        #
        return codelist
    #
#