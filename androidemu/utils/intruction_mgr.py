import os
import capstone
import keystone

class IntructionManger:
    
    def __init__(self, is_thumb):
        self.__is_thumb = is_thumb
        if (is_thumb):
            self.__cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
            self.__ks = keystone.Ks(keystone.KS_ARCH_ARM, keystone.KS_MODE_THUMB)
            self.__ins_sz = 2
        else:
            self._cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
            self.__ks = keystone.Ks(keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM) 
            self.__ins_sz = 4
        #
    #

    def asm(self, ins_str, offset):
        sa = ins_str.split(" ")
        if (len(sa) > 1):
            if (ins_str[0] == "b" and not ins_str.startswith("bic")):
                op = sa[1]
                if (op[0] == "#"):
                    op = op[1:]
                #
                if (op.startswith("0x")):
                    imm = int(op, 16)
                    rel = imm - offset - 2*self.__ins_sz
                    ins_str2 = "%s #%x"%(sa[0], rel)
                    #由于keystone的thumb2指令相对地址计算有bug，
                    #当指令是b.w，bne.w等w跳转指令会直接忽略offset参数
                    #所以这类指令我们不使用offset参数，自己计算偏移
                    return self.__ks.asm(ins_str2, 0)
                #
            #
        #
        return self.__ks.asm(ins_str, offset)
    #

    def disasm(self, code_bytes, offset):
        return self.__cs.disasm(code_bytes, offset)
    #
#