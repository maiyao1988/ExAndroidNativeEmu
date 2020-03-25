import json
import os
from os import stat_result

from unicorn import Uc

def _get_def_dic():
   return {
        'st_dev': 0,
        '__st_ino': 0,
        'st_mode': 0,
        'st_nlink': 0,
        'st_uid': 0,
        'st_gid': 0,
        'st_rdev': 0,
        'st_size': 0,
        'st_blksize': 0,
        'st_blocks': 0,
        'st_atime': 0,
        'st_atime_ns': 0,
        'st_mtime': 0,
        'st_mtime_ns': 0,
        'st_ctime': 0,
        'st_ctime_ns': 0,
        'st_ino': 0
    }
#
def stat64(path):
    if (path == None):
        return _get_def_dic()
    #
    meta_path = path + '.meta_emu'

    if not os.path.exists(meta_path):
        meta_path_dir = os.path.dirname(meta_path)

        if not os.path.isdir(meta_path_dir):
            os.makedirs(meta_path_dir)

        with open(meta_path, 'w') as f:
            json.dump(_get_def_dic(), fp=f, indent=4)
        #
    #
    
    with open(meta_path, 'r') as f:
        return json.load(fp=f)

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

    uc.mem_write(buf_ptr, int(stat.st_dev).to_bytes(8, byteorder='little'))
    uc.mem_write(buf_ptr + 8, int(0).to_bytes(4, byteorder='little'))  # PAD 4
    uc.mem_write(buf_ptr + 12, int(stat.st_ino).to_bytes(4, byteorder='little'))
    uc.mem_write(buf_ptr + 16, int(stat.st_mode).to_bytes(4, byteorder='little'))
    uc.mem_write(buf_ptr + 20, int(stat.st_nlink).to_bytes(4, byteorder='little'))
    uc.mem_write(buf_ptr + 24, int(uid).to_bytes(4, byteorder='little'))
    uc.mem_write(buf_ptr + 28, int(uid).to_bytes(4, byteorder='little'))
    uc.mem_write(buf_ptr + 32, int(stat.st_rdev).to_bytes(8, byteorder='little'))
    uc.mem_write(buf_ptr + 40, int(0).to_bytes(4, byteorder='little'))  # PAD 4
    uc.mem_write(buf_ptr + 48, int(stat.st_size).to_bytes(8, byteorder='little'))
    uc.mem_write(buf_ptr + 56, int(stat.st_blksize).to_bytes(4, byteorder='little'))
    uc.mem_write(buf_ptr + 64, int(stat.st_blocks).to_bytes(8, byteorder='little'))

    uc.mem_write(buf_ptr + 72, int(stat.st_atime).to_bytes(8, byteorder='little'))
    uc.mem_write(buf_ptr + 80, int(stat.st_mtime).to_bytes(8, byteorder='little'))
    uc.mem_write(buf_ptr + 88, int(stat.st_ctime).to_bytes(8, byteorder='little'))

    uc.mem_write(buf_ptr + 96, int(stat.st_ino).to_bytes(8, byteorder='little'))
#