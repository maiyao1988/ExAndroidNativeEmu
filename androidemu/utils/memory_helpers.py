import struct
from unicorn.arm_const import *

def read_ptr(mu, address):
    return int.from_bytes(mu.mem_read(address, 4), byteorder='little')


def read_byte_array(mu, address, size):
    return mu.mem_read(address, size)


def read_utf8(mu, address):
    buffer_address = address
    buffer_read_size = 32
    buffer = b""
    null_pos = None

    # Keep reading until we read something that contains a null terminator.
    while null_pos is None:
        buf_read = mu.mem_read(buffer_address, buffer_read_size)
        if b'\x00' in buf_read:
            null_pos = len(buffer) + buf_read.index(b'\x00')
        buffer += buf_read
        buffer_address += buffer_read_size

    return buffer[:null_pos].decode("utf-8")


def read_uints(mu, address, num=1):
    data = mu.mem_read(address, num * 4)
    return struct.unpack("I" * num, data)


def write_utf8(mu, address, value):
    mu.mem_write(address, value.encode(encoding="utf-8") + b"\x00")


def write_uints(mu, address, num):
    l = []
    if not isinstance(num, list):
        l = [num]
    else:
        l = num

    for v in l:
        mu.mem_write(address, int(v).to_bytes(4, byteorder='little'))
        address += 4
    #
#

def reg_context_save(mu):
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
    return (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, sp, lr, pc, cpsr)
#

def reg_context_restore(mu, ctx):
    mu.reg_write(UC_ARM_REG_R0, ctx[0])
    mu.reg_write(UC_ARM_REG_R1, ctx[1])
    mu.reg_write(UC_ARM_REG_R2, ctx[2])
    mu.reg_write(UC_ARM_REG_R3, ctx[3])
    mu.reg_write(UC_ARM_REG_R4, ctx[4])
    mu.reg_write(UC_ARM_REG_R5, ctx[5])
    mu.reg_write(UC_ARM_REG_R6, ctx[6])
    mu.reg_write(UC_ARM_REG_R7, ctx[7])
    mu.reg_write(UC_ARM_REG_R8, ctx[8])
    mu.reg_write(UC_ARM_REG_R9, ctx[9])
    mu.reg_write(UC_ARM_REG_R10, ctx[10])
    mu.reg_write(UC_ARM_REG_R11, ctx[11])
    mu.reg_write(UC_ARM_REG_R12, ctx[12])
    mu.reg_write(UC_ARM_REG_SP, ctx[13])
    mu.reg_write(UC_ARM_REG_LR, ctx[14])
    mu.reg_write(UC_ARM_REG_PC, ctx[15])
    mu.reg_write(UC_ARM_REG_CPSR, ctx[16])
#