
import capstone
import os
from unicorn import *
from unicorn.arm_const import *

def dump_memory(mu, fd, min_addr=0, max_addr=0xFFFFFFFF):
    line_connt = 16
    offset = 0
    regions = []
    for r in mu.mem_regions():
        regions.append(r)
    #
    regions.sort()
    for r in regions:
        offset = r[0]
        fd.write("region (0x%08X-0x%08X) prot:%d\n"%(r[0], r[1], r[2]))
        for addr in range(r[0], r[1]+1):
            if (addr < min_addr or addr > max_addr):
                continue
            #
            if (offset % line_connt == 0):
                fd.write("0x%08X: "%offset)
            #
            b = mu.mem_read(addr, 1).hex().upper()
            fd.write(" %s"%b)
            offset = offset + 1
            if (offset % line_connt == 0):
                fd.write("\n")
            #
        #
    #
#

def dump_registers(mu, fd):
    r0 = mu.reg_read(UC_ARM_REG_R0)
    r1 = mu.reg_read(UC_ARM_REG_R1)
    r2 = mu.reg_read(UC_ARM_REG_R2)
    r3 = mu.reg_read(UC_ARM_REG_R3)
    r4 = mu.reg_read(UC_ARM_REG_R4)
    r5 = mu.reg_read(UC_ARM_REG_R5)
    r6 = mu.reg_read(UC_ARM_REG_R6)
    r7 = mu.reg_read(UC_ARM_REG_R7)
    r8 = mu.reg_read(UC_ARM_REG_R8)
    r9 = mu.reg_read(UC_ARM_REG_R8)
    r10 = mu.reg_read(UC_ARM_REG_R10)
    r11 = mu.reg_read(UC_ARM_REG_R11)
    r12 = mu.reg_read(UC_ARM_REG_R12)
    sp =  mu.reg_read(UC_ARM_REG_SP)
    lr = mu.reg_read(UC_ARM_REG_LR)
    pc = mu.reg_read(UC_ARM_REG_PC)
    cpsr = mu.reg_read(UC_ARM_REG_CPSR)
    regs = "\tR0=0x%08X,R1=0x%08X,R2=0x%08X,R3=0x%08X,R4=0x%08X,R5=0x%08X,R6=0x%08X,R7=0x%08X,\n\tR8=0x%08X,R9=0x%08X,R10=0x%08X,R11=0x%08X,R12=0x%08X\n\tLR=0x%08X,PC=0x%08X, SP=0x%08X,CPSR=0x%08X"\
        %(r0, r1, r2, r3, r4, r5, r6, r7, r8, r9,r10,r11,r12, lr, pc, sp, cpsr)
    fd.write(regs+"\n")
#

def dump_symbols(emulator, fd):
    for m in emulator.modules:
        for addr in m.symbol_lookup:
            v = m.symbol_lookup[addr]
            fd.write("0x%08X(0x%08X):%s\n"%(addr, addr - m.base, v[0]))
        #
    #
#


g_md_thumb = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
g_md_thumb.detail = True

g_md_arm = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
g_md_arm.detail = True

def get_module_by_addr(emu, addr):
    ms = emu.modules
    module = None
    for m in ms:
        if (addr >= m.base and addr <= m.base+m.size):
            module = m
            break
        #
    #
    return module
#

# print code and its moudle in a line
def dump_code(emu, address, size, fd):

    #判断是否arm，用不同的decoder
    mu = emu.mu
    cpsr = mu.reg_read(UC_ARM_REG_CPSR)
    if (cpsr & (1<<5)):
        md = g_md_thumb
    else:
        md = g_md_arm
    #
    
    instruction = mu.mem_read(address, size)
    codes = md.disasm(instruction, address)
    m = 0
    for i in codes:
        addr = i.address

        name = "unknown"
        module = None
        base = 0
        funName = None
        module = get_module_by_addr(emu, addr)
        if (module != None):
            name = os.path.basename(module.filename)
            base = module.base
            funName = module.is_symbol_addr(addr)
        #

        instruction_str = ''.join('{:02X} '.format(x) for x in i.bytes)
        line = "(%20s[0x%08X])[%-12s]0x%08X:\t%s\t%s"%(name, base, instruction_str, addr-base, i.mnemonic.upper(), i.op_str.upper())
        if (funName != None):
            line = line + " ; %s"%funName
        #

        regs_read = i.regs_access()[0]
        regs = ""
        for rid in regs_read:
            regs = regs +"%s=0x%08X "%(i.reg_name(rid).upper(), mu.reg_read(rid))
        #
        if (regs != ""):
            line = "%s\t;(%s)"%(line, regs)
        #
        fd.write(line+"\n")
#