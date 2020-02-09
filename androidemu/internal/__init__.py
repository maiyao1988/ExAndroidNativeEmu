import ctypes

PF_X = 0x1  # Executable
PF_W = 0x2  # Writable
PF_R = 0x4  # Readable

PAGE_SIZE=0x1000


def page_start(addr):
    return addr & (~(PAGE_SIZE-1))
#

def page_end(addr):
    return page_start(addr)+PAGE_SIZE
#

def get_segment_protection(prot_in):
    prot = 0

    if prot_in & PF_R is not 0:
        prot |= 1

    if prot_in & PF_W is not 0:
        prot |= 2

    if prot_in & PF_X is not 0:
        prot |= 4

    return prot
