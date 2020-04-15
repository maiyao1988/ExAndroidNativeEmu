import json
import os
from os import stat_result

from unicorn import Uc

def stat_to_memory2(uc, buf_ptr, stat, uid):
    '''
    unsigned long long st_dev; 
    unsigned char __pad0[4]; 
    unsigned long __st_ino; 
    unsigned int st_mode; 
    nlink_t st_nlink;  4
    uid_t st_uid;  4
    gid_t st_gid; 4
    unsigned long long st_rdev; 
    unsigned char __pad3[4]; 
    long long st_size; 
    unsigned long st_blksize; 
    unsigned long long st_blocks; 
    struct timespec st_atim;  8
    struct timespec st_mtim;  8
    struct timespec st_ctim;  8
    unsigned long long st_ino; 

    '''
    st_rdev = 0
    if (hasattr(stat, "st_rdev")):
        st_rdev = stat.st_rdev
    #
    st_blksize = 0
    if (hasattr(stat, "st_blksize")):
        st_blksize = stat.st_blksize
    #
    st_blocks = 0
    if (hasattr(stat, "st_blocks")):
        st_blocks = stat.st_blocks
    #
    uc.mem_write(buf_ptr, int(stat.st_dev).to_bytes(8, byteorder='little'))
    uc.mem_write(buf_ptr + 8, int(0).to_bytes(4, byteorder='little'))  # PAD 4
    uc.mem_write(buf_ptr + 12, int(stat.st_ino).to_bytes(4, byteorder='little'))
    uc.mem_write(buf_ptr + 16, int(stat.st_mode).to_bytes(4, byteorder='little'))
    uc.mem_write(buf_ptr + 20, int(stat.st_nlink).to_bytes(4, byteorder='little'))
    uc.mem_write(buf_ptr + 24, int(uid).to_bytes(4, byteorder='little'))
    uc.mem_write(buf_ptr + 28, int(uid).to_bytes(4, byteorder='little'))
    uc.mem_write(buf_ptr + 32, int(st_rdev).to_bytes(8, byteorder='little'))
    uc.mem_write(buf_ptr + 40, int(0).to_bytes(4, byteorder='little'))  # PAD 4
    uc.mem_write(buf_ptr + 48, int(stat.st_size).to_bytes(8, byteorder='little'))
    uc.mem_write(buf_ptr + 56, int(st_blksize).to_bytes(4, byteorder='little'))
    uc.mem_write(buf_ptr + 64, int(st_blocks).to_bytes(8, byteorder='little'))

    uc.mem_write(buf_ptr + 72, int(stat.st_atime).to_bytes(8, byteorder='little'))
    uc.mem_write(buf_ptr + 80, int(stat.st_mtime).to_bytes(8, byteorder='little'))
    uc.mem_write(buf_ptr + 88, int(stat.st_ctime).to_bytes(8, byteorder='little'))

    uc.mem_write(buf_ptr + 96, int(stat.st_ino).to_bytes(8, byteorder='little'))
#