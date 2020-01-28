import logging
import sys
import io
from unicorn.arm_const import *

logger = logging.getLogger(__name__)


def hook_code(mu, address, size, user_data):
    instruction = mu.mem_read(address, size)
    instruction_str = ''.join('{:02x} '.format(x) for x in instruction)

    logger.debug('# Tracing instruction at 0x%x, instruction size = 0x%x, instruction = %s' %
                 (address, size, instruction_str))

    if instruction == b"\x00\x00\x00\x00":
        logger.error("Uh oh, we messed up.")
        mu.emu_stop()


def hook_unmapped(mu, access, address, length, value, context):
    pc = mu.reg_read(UC_ARM_REG_PC)

    logger.debug("mem unmapped: pc: %x access: %x address: %x length: %x value: %x" %
                 (pc, access, address, length, value))
    mu.emu_stop()
    return True


def hook_mem_write(uc, access, address, size, value, user_data):
    pc = uc.reg_read(UC_ARM_REG_PC)
    logger.debug(">>> Memory WRITE at 0x%x, data size = %u, data value = 0x%x, pc: %x" % (address, size, value, pc))


def hook_mem_read(uc, access, address, size, value, user_data):
    pc = uc.reg_read(UC_ARM_REG_PC)
    data = uc.mem_read(address, size)
    logger.debug(">>> Memory READ at 0x%x, data size = %u, pc: %x, data value = 0x%s" % (address, size, pc, data.hex()))


def hook_interrupt(uc, intno, data):
    logger.debug(">>> Triggering interrupt %d" % intno)
    return


def dump_memory(uc, fd, min_addr=0, max_addr=0xFFFFFFFF):
    line_connt = 16
    offset = 0
    regions = []
    for r in uc.mem_regions():
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
            b = uc.mem_read(addr, 1).hex().upper()
            fd.write(" %s"%b)
            offset = offset + 1
            if (offset % line_connt == 0):
                fd.write("\n")
            #
        #
    #
#
