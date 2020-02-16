import os
import capstone
import keystone

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

    def disasm(self, code_bytes, offset):
        return self.__cs.disasm(code_bytes, offset)
    #
#