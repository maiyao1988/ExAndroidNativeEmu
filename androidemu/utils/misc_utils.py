import os.path
import os
import platform

import platform
from ..const import emu_const

from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *

g_isWin = platform.system() == "Windows"

def vfs_path_to_system_path(vfs_root, path):
    if os.name == 'nt':
        path = path.replace(':', '_')
    #
    fullpath = "%s/%s"%(vfs_root, path)
    return fullpath
#

def system_path_to_vfs_path(vfs_root, path):
    return "/"+os.path.relpath(path, vfs_root)
#

PF_X = 0x1  # Executable
PF_W = 0x2  # Writable
PF_R = 0x4  # Readable

PAGE_SIZE=0x1000


def page_start(addr):
    return addr & (~(PAGE_SIZE-1))
#

def page_end(addr):
    return page_start(addr+(PAGE_SIZE-1))
#

def get_segment_protection(prot_in):
    prot = 0

    if prot_in & PF_R != 0:
        prot |= 1

    if prot_in & PF_W != 0:
        prot |= 2

    if prot_in & PF_X != 0:
        prot |= 4

    return prot
#

def my_open(fd, flag):
    global g_isWin
    if(g_isWin):
        flag = flag | os.O_BINARY
    #
    return os.open(fd, flag)
#


def set_errno(emu, errno):
    mu = emu.mu
    if (emu.get_arch() == emu_const.ARCH_ARM32):
        err_ptr = mu.reg_reg(UC_ARM_REG_C13_C0_3) + 8
        mu.mem_write(err_ptr, int(errno).to_bytes(4, byteorder='little'))
    #
    else:
        err_ptr = mu.reg_write(UC_ARM64_REG_TPIDR_EL0) + 16
        #errno 是int，只写四个字节
        mu.mem_write(err_ptr, int(errno).to_bytes(4, byteorder='little'))
    #
#