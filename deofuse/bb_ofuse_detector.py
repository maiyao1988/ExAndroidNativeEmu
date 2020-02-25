from deofuse.intruction_mgr import IntructionManger
from deofuse.ins_helper import *
from deofuse import cfg
from deofuse import tracer

def _start_withs(str, sets):
    for s in sets:
        if (str.startswith(s)):
            return True
        #
    #
    return False
#
#bangbang control example
'''
loc_1D090               ; 77
DB8 0B 2B       CMP             R3, #0xB
DB8 FB D8       BHI             def_1D094 ; 7

loc_1D022               ; 2
DB8 C9 B9       CBNZ            R1, loc_1D058

DB8 FE F7 97 BF B.W             loc_1CDEA

DB8 DF E8 03 F0 TBB.W           [PC,R3] ; 77

loc_1DF30               ; jumptable 0001DE8A case 0
DB8 06 23       MOVS            R3, #6
DB8 A6 E7       B               loc_1DE82

loc_1B500               ; 1
DB8 09 22       MOVS            R2, #9

loc_1DE82
DB8 01 3B       SUBS            R3, #1
DB8 05 2B       CMP             R3, #5  ; switch 6 cases
DB8 3E F6 AD AF BHI.W           def_1DE8A ; jumptable 0001DE8A default case
'''
class BBOfDetector:
    def __init__(self):
        pass
    #

    def find_ofuse_control_block(self, f, blocks, base_addr, ins_mgr):
        obfuses_cb = []
        dead_cb = []

        for b in blocks:
            #print(b)

            codelist = get_block_codes(f, b, ins_mgr)
            
            n = len(codelist)

            if (n < 2):
            #只有一条指令而且跳回给自己的是死块
                if (n == 1):
                    jmp_addr = get_jmp_dest(codelist[0])
                    if (jmp_addr != None and jmp_addr == b.start):
                        dead_cb.append(b)
                        continue
                    #
                #
            #
            if (n < 4):
                is_cb = True
                no_cb_op = ["push", "pop", "bl", "blx"]
                spspect_op = ["ldr", "str"]
                if (n == 1 and codelist[0].mnemonic == "b"):
                    #只有一个条指令就是b的话，不认为是控制块，不存在任何条件
                    continue
                #
                for j in range(0, n):
                    mne = codelist[j].mnemonic
                    if (_start_withs(mne, no_cb_op)):
                        if (mne.startswith("ble")):
                            continue
                        #
                        is_cb = False
                        break
                    #
                    if (_start_withs(mne, spspect_op)):
                        print("BBOfDetector warning block %r is short but has ldr/str please check, treat as ofuse block"%b)
                    #
                #
                if (is_cb):
                    obfuses_cb.append(b)
                #
            #

        #
        return obfuses_cb, dead_cb
    #
#