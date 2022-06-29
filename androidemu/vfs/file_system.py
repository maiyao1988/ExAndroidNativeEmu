import logging
import os
import posixpath
import sys
from ..const.linux import *
from .. import config
from ..config import WRITE_FSTAT_TIMES
from ..cpu.syscall_handlers import SyscallHandlers
from ..utils import memory_helpers,misc_utils
from ..const import emu_const
from . import file_helpers
from .. import pcb
from ..const import linux
import platform
import shutil
import random
import select

g_isWin = platform.system() == "Windows"
if not g_isWin:
    import fcntl
#

OVERRIDE_URANDOM = False
OVERRIDE_URANDOM_INT = 1

#status
s_status = '''
Name:   {pkg_name}
State:  R (running)
Tgid:   1434
Pid:    1434
PPid:   197
TracerPid:      0
Uid:    10054   10054   10054   10054
Gid:    10054   10054   10054   10054
FDSize: 512
Groups: 1015 1028 3003 50054 
VmPeak:  1229168 kB
VmSize:  1115232 kB
VmLck:         0 kB
VmPin:         0 kB
VmHWM:    179992 kB
VmRSS:    179836 kB
VmData:   191904 kB
VmStk:       136 kB
VmExe:         8 kB
VmLib:     48448 kB
VmPTE:       536 kB
VmSwap:        0 kB
Threads:        105
SigQ:   0/12272
SigPnd: 0000000000000000
ShdPnd: 0000000000000000
SigBlk: 0000000000001204
SigIgn: 0000000000000000
SigCgt: 00000002000094f8
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: fffffff000000000
Cpus_allowed:   f
Cpus_allowed_list:      0-3
voluntary_ctxt_switches:        5225
nonvoluntary_ctxt_switches:     11520
'''

class VirtualFileSystem:

    def __translate_path(self, filename):
        return misc_utils.vfs_path_to_system_path(self._root_path, filename)
    #

    def __clear_proc_dir(self):
        proc = "/proc"
        proc = self.__translate_path(proc)
        dirs = os.listdir(proc)
        for d in dirs:
            if (d.isdigit()):
                fp = "%s/%s/"%(proc, d)
                shutil.rmtree(fp)
            #
        #
    #

    """
    :type syscall_handler SyscallHandlers
    """
    def __init__(self, emu, root_path, cfg, syscall_handler, memory_map):
        self.__emu = emu
        self._root_path = root_path
        self.__cfg = cfg
        self.__memory_map = memory_map
        self.__pcb = emu.get_pcb()
        self.__clear_proc_dir()
        self.__root_list = set(["/dev/__properties__"])
        if (self.__emu.get_arch() == emu_const.ARCH_ARM32):
            syscall_handler.set_handler(0x3, "read", 3, self._handle_read)
            syscall_handler.set_handler(0x4, "write", 3, self._handle_write)
            syscall_handler.set_handler(0x5, "open", 3, self._handle_open)
            syscall_handler.set_handler(0x6, "close", 1, self._handle_close)
            syscall_handler.set_handler(0x0A, "unlink", 1, self._handle_unlink)
            syscall_handler.set_handler(0x13, "lseek", 3, self._handle_lseek)
            syscall_handler.set_handler(0x21, "access", 2, self._handle_access)
            syscall_handler.set_handler(0x27, "mkdir", 2, self.__mkdir)
            syscall_handler.set_handler(0x36, "ioctl", 6, self.__ioctl)
            syscall_handler.set_handler(0x37, "fcntl", 6, self.__fcntl64)
            syscall_handler.set_handler(0x6C, "fstat", 2, self._handle_fstat64)
            syscall_handler.set_handler(0x8c, "_llseek", 5, self._handle_llseek)
            syscall_handler.set_handler(0x92, "writev", 3, self._handle_writev)
            syscall_handler.set_handler(0xA8, "poll", 3, self._handle_poll)
            syscall_handler.set_handler(0xC3, "stat64", 2, self._handle_stat64)
            syscall_handler.set_handler(0xC4, "lstat64", 2, self._handle_lstat64)
            syscall_handler.set_handler(0xC5, "fstat64", 2, self._handle_fstat64)
            syscall_handler.set_handler(0xD9, "getdents64", 3, self._handle_getdents64)
            syscall_handler.set_handler(0xDD, "fcntl64", 6, self.__fcntl64)
            syscall_handler.set_handler(0x10A, "statfs64", 3, self.__statfs64)
            syscall_handler.set_handler(0x142, "openat", 4, self._handle_openat)
            syscall_handler.set_handler(0x143, "mkdirat", 3, self.__mkdirat)
            syscall_handler.set_handler(0x147, "fstatat64", 4, self._handle_fstatat64)
            syscall_handler.set_handler(0x148, "unlinkat", 3, self.__unlinkat)
            syscall_handler.set_handler(0x14c, "readlinkat", 4, self.__readlinkat)
            syscall_handler.set_handler(0x14e, "faccessat", 4, self._faccessat)
            syscall_handler.set_handler(0x150, "ppoll", 4, self.__ppoll)

        else:
            #arm64
            syscall_handler.set_handler(0x3f, "read", 3, self._handle_read)
            syscall_handler.set_handler(0x40, "write", 3, self._handle_write)
            #no open syscall in arm64
            syscall_handler.set_handler(0x39, "close", 1, self._handle_close)
            #no unlink syscall
            syscall_handler.set_handler(0x3e, "lseek", 3, self._handle_lseek)
            #no access syscall
            #no mkdir
            syscall_handler.set_handler(0x1d, "ioctl", 6, self.__ioctl)
            syscall_handler.set_handler(0x19, "fcntl", 6, self.__fcntl64)
            syscall_handler.set_handler(0x50, "fstat", 2, self._handle_fstat64)

            #no _lllseek
            syscall_handler.set_handler(0x42, "writev", 3, self._handle_writev)
            #no poll
            #no stat64
            #no lstat64
            #no fstat64 use fstat
            syscall_handler.set_handler(0x3D, "getdents64", 3, self._handle_getdents64)
            #no fcntl64
            #no statfs64

            syscall_handler.set_handler(0x2B, "statfs", 3, self.__statfs64)
            syscall_handler.set_handler(0x38, "openat", 4, self._handle_openat)
            syscall_handler.set_handler(0x22, "mkdirat", 3, self.__mkdirat)
            #no fstatat64

            syscall_handler.set_handler(0x23, "unlinkat", 3, self.__unlinkat)
            syscall_handler.set_handler(0x4E, "readlinkat", 4, self.__readlinkat)
            syscall_handler.set_handler(0x30, "faccessat", 4, self._faccessat)
            syscall_handler.set_handler(0x49, "ppoll", 4, self.__ppoll)

            syscall_handler.set_handler(0x4F, "newfstatat", 4, self._handle_fstatat64)

        #

    #

    def __create_fd_link(self, fd, target):
        global g_isWin
        if (g_isWin):
            return
        #
        if (fd >= 0):
            pid = self.__pcb.get_pid()
            fdbase = "/proc/%d/fd/"%pid
            fdbase = self.__translate_path(fdbase)
            if (not os.path.exists(fdbase)):
                os.makedirs(fdbase)
            #
            p = "%s/%d"%(fdbase, fd)
            if (os.path.exists(p)):
                os.remove(p)
            #
            full_target = os.path.abspath(target)
            os.symlink(full_target, p, False)
        #
    #

    def __del_fd_link(self, fd):
        global g_isWin
        if (g_isWin):
            return
        #
        if (fd >= 0):
            pid = self.__pcb.get_pid()
            fdbase = "/proc/%d/fd/"%pid
            fdbase = self.__translate_path(fdbase)
            p = "%s/%d"%(fdbase, fd)
            if (os.path.exists(p)):
                os.remove(p)
            #
        #
    #

    def _open_file(self, filename, oflag):
        #define O_RDONLY 00000000
        #define O_WRONLY 00000001
        #define O_RDWR 00000002
        #ifndef O_CREAT
        #define O_CREAT 00000100
        # Special cases, such as /dev/urandom.

        file_path = self.__translate_path(filename)
        if filename == '/dev/urandom':
            logging.debug("File opened '%s'" % filename)
            parent = os.path.dirname(file_path)
            if (not os.path.exists(parent)):
                os.makedirs(parent)
            #
            with open(file_path, "wb") as f:
                ran = OVERRIDE_URANDOM_INT
                if (not OVERRIDE_URANDOM):
                    ran = random.randint(1, 1<<128)
                #
                b = int(ran).to_bytes(128, byteorder='little')
                f.write(b)
            #
        #
        elif (filename.startswith("/proc/")):
            #simulate proc file system
            parent = os.path.dirname(file_path)
            if (not os.path.exists(parent)):
                os.makedirs(parent)
            #
            
            pobj = self.__pcb
            pid = pobj.get_pid()
            filename2 = filename.replace(str(pid), "self")
            #TODO: move pid to config

            map_path = "/proc/self/maps"
            if (filename2 == map_path):
                with open(file_path, "w") as f:
                    self.__memory_map.dump_maps(f)
                #
            #
            cmdline_path = "/proc/self/cmdline"
            if (filename2 == cmdline_path):
                with open(file_path, "w") as f:
                    #TODO put to config
                    content = self.__cfg.get("pkg_name")
                    f.write(content)
                #
            #
            cgroup_path = "/proc/self/cgroup"
            if (filename2 == cgroup_path):
                with open(file_path, "w") as f:
                    #TODO put to config
                    uid = self.__get_config_uid(filename)
                    content = "2:cpu:/apps\n1:cpuacct:/uid/%d\n"%uid
                    f.write(content)
                #
            #
            status_path = "/proc/self/status"
            if (filename2 == status_path):
                with open(file_path, "w") as f:
                    #TODO put to config
                    name = self.__cfg.get("pkg_name")
                    content = s_status.format(pkg_name=name)
                    f.write(content)
                #
            #
            
            
        #
        virtual_file = ["/dev/log/main", "/dev/log/events", "/dev/log/radio", "/dev/log/system",  "/dev/input/event0"]
        if (filename in virtual_file):
            d = os.path.dirname(file_path)
            if (not os.path.exists(d)):
                os.makedirs(d)
            #
            with open(file_path, "w") as f:
                pass
            #
        #
        if os.path.exists(file_path):
            if (oflag & 0o00000001):
                flags = os.O_RDWR
            elif (oflag & 0o00000002):
                flags = os.O_RDWR
            else:#0
                flags = os.O_RDONLY
            
            if (oflag & 0o100):
                flags |= os.O_CREAT
            #
            if (oflag & 0o2000):
                flags |= os.O_APPEND
            #
            if (oflag & 0o40000):
                flags |= os.O_DIRECTORY
            #
            if (oflag & 0o010000000):
                flags |= os.O_PATH
            #
            fd = misc_utils.my_open(file_path, flags)
            self.__pcb.add_fd(filename, file_path, fd)
            logging.info("open [%s][0x%x] return fd %d"%(file_path, oflag, fd))
            self.__create_fd_link(fd, file_path)
            return fd
        else:
            logging.warning("File does not exist '%s'" % filename)
            return -1
        #
    #

    def __dirfd_2_path(self, dirfd, relpath):
        if (dirfd == linux.AT_FDCWD):
            return relpath
        #
        if (os.path.isabs(relpath)):
            #绝对路径，直接忽略
            return relpath
        #
        else:
            fdesc = self.__pcb.get_fd_detail(dirfd)
            if (fdesc == None):
                #fd不存在，可能是bug...要看被模拟的程序逻辑
                logging.info("dirfd %d is invalid!!!"%dirfd)
                return None
            #
            dirpath = fdesc.name
            path = os.path.join(dirpath, relpath)
            return path
        #
    #

    def __norm_file_name(self, filename_in_vm):
        filename_norm = os.path.normpath(filename_in_vm)
        global g_isWin
        if (g_isWin):
            #windows的路径标准化之后是反斜杠的，这里换成linux的正斜杠
            filename_norm = filename_norm.replace("\\", "/")
        #
        return filename_norm
    #

    def __get_config_uid(self, filename_in_vm):
        filename_norm = self.__norm_file_name(filename_in_vm)
        uid = 0
        #注意linux c打开/dev/__properties__检测是不是root，如果不是root初始化失败而崩溃,如果其他组或者本组用户可写也会崩溃！！！
        if (filename_norm in self.__root_list):
            uid = 0
        #
        else:
            uid = self.__cfg.get("uid")
        return uid
    #

    def __fix_st_mode(self, filename_in_vm, st_mode):
        filename_norm = self.__norm_file_name(filename_in_vm)
        #注意linux c打开/dev/__properties__检测是不是root，如果不是root初始化失败而崩溃,如果其他组或者本组用户可写也会崩溃！！！
        if (filename_norm in self.__root_list):
            #在root里面其他组和本组不可写
            st_mode = st_mode & (~0o0000020) #S_IWGRP
            st_mode = st_mode & (~0o0000002) #S_IWOTH
        #
        return st_mode
    #

    def _handle_read(self, mu, fd, buf_addr, count):
        """
        ssize_t read(int fd, void *buf, size_t count);

        On files that support seeking, the read operation commences at the current file offset, and the file offset
        is incremented by the number of bytes read. If the current file offset is at or past the end of file,
        no bytes are read, and read() returns zero.

        If count is zero, read() may detect the errors described below. In the absence of any errors, or if read()
        does not check for errors, a read() with a count of 0 returns zero and has no other effects.

        If count is greater than SSIZE_MAX, the result is unspecified.
        """
        if fd <= 2:
            logging.warning("skip read for fd %d"%fd)
            return 0
            #raise NotImplementedError("Unsupported read operation for file descriptor %d." % fd)
        #

        file = self.__pcb.get_fd_detail(fd)
        logging.debug("Reading %d bytes from '%s'" % (count, file.name))

        buf = os.read(fd, count)

        logging.debug("read return %s"%buf.hex())
        result = len(buf)
        mu.mem_write(buf_addr, buf)
        return result

    def _handle_write(self, mu, fd, buf_addr, count):
        
        data = mu.mem_read(buf_addr, count)
        if (fd == 1):
            s = bytes(data).decode("utf-8")
            logging.debug("stdout:[%s]"%s)
            return len(data)
        elif(fd == 2):
            s = bytes(data).decode("utf-8")
            logging.warning("stderr:[%s]"%s)
            return len(data)
        #

        try:
            r = os.write(fd, data)
        except OSError as e:
            file = self.__pcb.get_fd_detail(fd)
            logging.warning("File write '%s' error %r skip" %(file.name, e))
            return -1
        #
        return r
    #

    def _handle_open(self, mu, filename_ptr, flags, mode):
        """
        int open(const char *pathname, int flags, mode_t mode);

        return the new file descriptor, or -1 if an error occurred (in which case, errno is set appropriately).
        """
        filename = memory_helpers.read_utf8(mu, filename_ptr)

        return self._open_file(filename, flags)

    def _handle_close(self, mu, fd):
        """
        int close(int fd);

        close() closes a file descriptor, so that it no longer refers to any file and may be reused. Any record locks
        (see fcntl(2)) held on the file it was associated with, and owned by the process, are removed (regardless of
        the file descriptor that was used to obtain the lock).

        close() returns zero on success. On error, -1 is returned, and errno is set appropriately.
        """
        try:
            if (self.__pcb.has_fd(fd)):
                self.__pcb.remove_fd(fd)
                os.close(fd)
                self.__del_fd_link(fd)
            else:
                #之前关闭过的直接返回0,与安卓系统行为一致
                logging.warning("fd 0x%08X not in fds maybe has closed, just return 0"%fd)
                return 0
        except OSError as e:
            logging.warning("fd %d close error."%fd)
            return -1
        #
        return 0
    
    def _handle_unlink(self, mu, path_ptr):
        path = memory_helpers.read_utf8(mu, path_ptr)
        vfs_path = self.__translate_path(path)
        logging.debug("unlink call path [%s]"%path)
        return 0
    #

    def _handle_lseek(self, mu, fd, offset, whence):
        return os.lseek(fd, offset, whence)
    #

    def _handle_access(self, mu, filename_ptr, flags):
        filename = memory_helpers.read_utf8(mu, filename_ptr)
        vfs_path = self.__translate_path(filename)
        rc = os.access(vfs_path, flags)
        r = -1
        if (rc):
            r = 0
        #
        logging.debug("access '%s' return %d" %(filename, r))
        return r
    #
    def __mkdir(self, mu, path_ptr, mode):
        path = memory_helpers.read_utf8(mu, path_ptr)
        vfs_path = self.__translate_path(path)

        logging.debug("mkdir call path [%s]"%path)
        if (not os.path.exists(vfs_path)):
            os.makedirs(vfs_path)
        #
        return 0
    #

    def _handle_writev(self, mu, fd, vec, vlen):
        n = 0
        ptr_sz = self.__emu.get_ptr_size()
        vec_sz = 2*ptr_sz
        for i in range(0, vlen):
            addr = memory_helpers.read_ptr_sz(mu, vec + (i * vec_sz), ptr_sz)
            size = memory_helpers.read_ptr_sz(mu, vec + (i * vec_sz) + ptr_sz, ptr_sz)
            data = bytes(mu.mem_read(addr, size))
            logging.debug('Writev %r' % data)
            n += os.write(fd, data)
        #
        return n
    #

    def __do_poll(self, mu, pollfd_ptr, nfds, timeout):
        
        '''
        struct pollfd {
            int    fd;       /* file descriptor */
            short  events;   /* events to look for */
            short  revents;  /* events returned */
        };
        '''
        if (hasattr(select, "poll")):
            p = select.poll()
            ptr = pollfd_ptr
            for i in range(0, nfds):
                fd = mu.mem_read(ptr, 4)
                events = mu.mem_read(ptr+4 , 2)
                p.register(int.from_bytes(fd, byteorder='little', signed=False), int.from_bytes(events, byteorder='little', signed=False))
                ptr = ptr + 8
            #
            logging.info("poll timeout %d"%timeout)
            poll_r = p.poll(timeout)
            logging.info("poll wakeup")
            ptr = pollfd_ptr
            for item in poll_r:
                for i in range(0, nfds):
                    fd = mu.mem_read(ptr, 4)
                    ifd = int.from_bytes(fd, byteorder='little', signed=False)
                    if item[0] == ifd:
                        mu.mem_write(ptr+6, int(item[1]).to_bytes(4, byteorder='little'))
                        break
                    #
                    ptr = ptr + 8
                #
            #
            return len(poll_r)
        #
        else:
            ptr = pollfd_ptr
            for i in range(0, nfds):
                fd = mu.mem_read(ptr, 4)
                events = mu.mem_read(ptr+4 , 2)
                mu.mem_write(ptr+6, bytes(events))
            #
            logging.warning("poll not support in this system skip, just return nfds %d"%nfds)
            return nfds
        #
    #

    def _handle_poll(self, mu, pollfd_ptr, nfds, timeout):
        return self.__do_poll(mu, pollfd_ptr, nfds, timeout)
    #
    
    def __ppoll(self, mu, pollfd_ptr, nfds, timeout_ts_ptr, sigmask_ptr):
        timeout = -1
        if timeout_ts_ptr != 0:
            ptr_sz = self.__emu.get_ptr_size()
            tv_sec = memory_helpers.read_ptr_sz(mu, timeout_ts_ptr, ptr_sz)
            tv_nsec = memory_helpers.read_ptr_sz(mu, timeout_ts_ptr + ptr_sz, ptr_sz)
            timeout = int(tv_sec * 1000 + tv_nsec / 1000000)
        #
        return self.__do_poll(mu, pollfd_ptr, nfds, timeout)
    #

    def _handle_stat64(self, mu, filename_ptr, buf_ptr):
        filename = memory_helpers.read_utf8(mu, filename_ptr)
        logging.debug("stat64 %s"%filename)

        file_path = self.__translate_path(filename)
        if (os.path.exists(file_path)):
            stats = os.stat(file_path)
            uid = self.__get_config_uid(filename)
            st_mode = self.__fix_st_mode(filename, stats.st_mode)
            file_helpers.stat_to_memory2(mu, buf_ptr, stats, uid, st_mode)
            return 0
        else:
            return -1
        #
    #

    def _handle_lstat64(self, mu, filename_ptr, buf_ptr):
        filename = memory_helpers.read_utf8(mu, filename_ptr)
        logging.debug("lstat64 %s"%filename)
        file_path = self.__translate_path(filename)
        if (os.path.exists(file_path)):
            stats = os.stat(file_path)
            uid = self.__get_config_uid(filename)
            st_mode = self.__fix_st_mode(filename, stats.st_mode)
            file_helpers.stat_to_memory2(mu, buf_ptr, stats, uid, st_mode)
            return 0
        else:
            return -1
        #
    #

    def _handle_fstat64(self, mu, fd, stat_ptr):
        detail = self.__pcb.get_fd_detail(fd)
        if (not detail):
            logging.warning("fstat64 invalid fd %d return -1"%fd)
            return -1
        #
        stats = os.fstat(fd)
        uid = self.__get_config_uid(detail.name)
        st_mode = self.__fix_st_mode(detail.name, stats.st_mode)
        if (self.__emu.get_arch() == emu_const.ARCH_ARM32):
            file_helpers.stat_to_memory2(mu, stat_ptr, stats, uid, st_mode)
        else:
            #64
            file_helpers.stat_to_memory64(mu, stat_ptr, stats, uid, st_mode)
        #
    #

    def _handle_getdents64(self, mu, fd, linux_dirent64_ptr, count):
        logging.warning("syscall _handle_getdents64 %u %u %u skip..."%(fd, linux_dirent64_ptr, count))
        return -1
    #

    def __ioctl(self, mu, fd, cmd, arg1, arg2, arg3, arg4):
        #http://man7.org/linux/man-pages/man2/ioctl_list.2.html
        #0x00008912   SIOCGIFCONF      struct ifconf *
        #TODO:ifconf struct is complex, implement it
        SIOCGIFCONF = 0x00008912
        logging.info("%x %x %x"%(fd, cmd, arg1))
        if (cmd == SIOCGIFCONF):
            #this is a way to get network address
            logging.info("warning ioctl SIOCGIFCONF to get net addrs not implemented return -1 and skip")
            return -1
        #
        raise NotImplementedError()
    #

    def __fcntl64(self, mu, fd, cmd, arg1, arg2, arg3, arg4):
        #fcntl is not support on windows
        global g_isWin
        if (g_isWin):
            return 0
        r = fcntl.fcntl(fd, cmd, arg1)
        return r
    #

    def _handle_llseek(self, mu, fd, offset_high, offset_low, result_ptr, whence):
        if (offset_high != 0):
            raise RuntimeError("_llseek offset_high %d>0 not implemented"%offset_high)
        #
        n = os.lseek(fd, offset_low, whence)
        r = -1
        if (n > 0xFFFFFFFF):
            raise RuntimeError("_llseek return > 32 bits not implemented!!!")
        if (n >= 0):
            r = 0
            rbytes = n.to_bytes(8, 'little')
            mu.mem_write(result_ptr, rbytes)
        #
        return r
    #

    def __statfs64(self, mu, path_ptr, sz, buf):        
        path = memory_helpers.read_utf8(mu, path_ptr)
        logging.debug("statfs64 path %s"%path)
        path = self.__translate_path(path)
        if (not os.path.exists(path)):
            return -1
        #
        statv = os.statvfs(path)
        '''
        f_type = {uint32_t} 61267
        f_bsize = {uint32_t} 4096
        f_blocks = {uint64_t} 3290543
        f_bfree = {uint64_t} 2499155
        f_bavail = {uint64_t} 2499155
        f_files = {uint64_t} 838832
        f_ffree = {uint64_t} 828427
        f_fsid = {fsid_t} 
            __val = {int [2]} 
        f_namelen = {uint32_t} 255
        f_frsize = {uint32_t} 4096
        f_flags = {uint32_t} 1062
        f_spare = {uint32_t [4]} 
        '''
        f_fsid = 0
        if (hasattr(statv, "f_fsid")):
            print(statv)
            f_fsid = statv.f_fsid
        #
        if (self.__emu.get_arch() == emu_const.ARCH_ARM32):
            mu.mem_write(buf, int(0xef53).to_bytes(4, 'little'))
            mu.mem_write(buf+4, int(statv.f_bsize).to_bytes(4, 'little'))
            mu.mem_write(buf+8, int(statv.f_blocks).to_bytes(8, 'little'))
            mu.mem_write(buf+16, int(statv.f_bfree).to_bytes(8, 'little'))
            mu.mem_write(buf+24, int(statv.f_bavail).to_bytes(8, 'little'))
            mu.mem_write(buf+32, int(statv.f_files).to_bytes(8, 'little'))
            mu.mem_write(buf+40, int(statv.f_ffree).to_bytes(8, 'little'))
            mu.mem_write(buf+48, int(f_fsid).to_bytes(8, 'little'))
            mu.mem_write(buf+56, int(statv.f_namemax).to_bytes(4, 'little'))
            mu.mem_write(buf+60, int(statv.f_frsize).to_bytes(4, 'little'))
            mu.mem_write(buf+64, int(statv.f_flag).to_bytes(4, 'little'))
            mu.mem_write(buf+68, int(0).to_bytes(16, 'little'))
        else:
            #arm64
            mu.mem_write(buf, int(0xef53).to_bytes(8, 'little'))
            mu.mem_write(buf+8, int(statv.f_bsize).to_bytes(8, 'little'))
            mu.mem_write(buf+16, int(statv.f_blocks).to_bytes(8, 'little'))
            mu.mem_write(buf+24, int(statv.f_bfree).to_bytes(8, 'little'))
            mu.mem_write(buf+32, int(statv.f_bavail).to_bytes(8, 'little'))
            mu.mem_write(buf+40, int(statv.f_files).to_bytes(8, 'little'))
            mu.mem_write(buf+48, int(statv.f_ffree).to_bytes(8, 'little'))
            mu.mem_write(buf+56, int(f_fsid).to_bytes(8, 'little'))
            mu.mem_write(buf+64, int(statv.f_namemax).to_bytes(8, 'little'))
            mu.mem_write(buf+72, int(statv.f_frsize).to_bytes(8, 'little'))
            mu.mem_write(buf+80, int(statv.f_flag).to_bytes(8, 'little'))
            mu.mem_write(buf+88, int(0).to_bytes(32, 'little'))
        #
        #raise NotImplementedError()
        return 0
    #

    def _handle_openat(self, mu, dfd, filename_ptr, flags, mode):
        """
        int openat(int dirfd, const char *pathname, int flags, mode_t mode);

        On success, openat() returns a new file descriptor.
        On error, -1 is returned and errno is set to indicate the error.

        EBADF
            dirfd is not a valid file descriptor.
        ENOTDIR
            pathname is relative and dirfd is a file descriptor referring to a file other than a directory.
        """
        filename = memory_helpers.read_utf8(mu, filename_ptr)
        filepath = self.__dirfd_2_path(dfd, filename)
        if (filepath == None):
            return -1
        #
        return self._open_file(filepath, flags)
    #


    def __mkdirat(self, mu, dfd, path_ptr, mode):
        path = memory_helpers.read_utf8(mu, path_ptr)

        path = self.__dirfd_2_path(dfd, path)
        if (path == None):
            return -1
        #
        vfs_path = self.__translate_path(path)

        logging.debug("mkdirat call path [%s]"%path)
        if (not os.path.exists(vfs_path)):
            os.makedirs(vfs_path)
        #
        return 0

    #
    def _handle_fstatat64(self, mu, dirfd, pathname_ptr, buf, flags):
        """
        int fstatat(int dirfd, const char *pathname, struct stat *buf, int flags);

        If the pathname given in pathname is relative, then it is interpreted relative to the directory referred
        to by the file descriptor dirfd (rather than relative to the current working directory of the calling process,
        as is done by stat(2) for a relative pathname).

        If pathname is relative and dirfd is the special value AT_FDCWD,
        then pathname is interpreted relative to the current working directory of the calling process (like stat(2)).

        If pathname is absolute, then dirfd is ignored.

        flags can either be 0, or include one or more of the following flags ..

        On success, fstatat() returns 0. On error, -1 is returned and errno is set to indicate the error.
        """
        pathname_vm = memory_helpers.read_utf8(mu, pathname_ptr)

        logging.debug("fstatat64 patename=[%s]"%pathname_vm)
        pathname_vm = self.__dirfd_2_path(dirfd, pathname_vm)
        if (pathname_vm == None):
            return -1
        #
        if not flags == 0:
            if flags & 0x100:  # AT_SYMLINK_NOFOLLOW
                pass
            if flags & 0x800:  # AT_NO_AUTOMOUNT
                pass
            # raise NotImplementedError("Flags has not been implemented yet.")

        logging.debug("File fstatat64 '%s'" % pathname_vm)
        pathname = self.__translate_path(pathname_vm)

        if not os.path.exists(pathname):
            logging.warning('> File was not found.')
            return -1
        #
        stat = os.stat(pathname)
        uid = self.__get_config_uid(pathname_vm)
        st_mode = self.__fix_st_mode(pathname_vm, stat.st_mode)

        # stat = os.stat(path=file_path, dir_fd=None, follow_symlinks=False)
        if (self.__emu.get_arch() == emu_const.ARCH_ARM32):
            file_helpers.stat_to_memory2(mu, buf, stat, uid, st_mode)
        else:
            #arm64
            file_helpers.stat_to_memory64(mu, buf, stat, uid, st_mode)
        return 0
    #

    def __unlinkat(self, mu, dfd, path_ptr, flag):
        path = memory_helpers.read_utf8(mu, path_ptr)
        logging.debug("unlinkat call dfd [%d] path [%s]"%(dfd, path))

        path = self.__dirfd_2_path(dfd, path)
        if (path == None):
            return -1
        #
        vfs_path = self.__translate_path(path)
        #TODO delete real file
    #

    def __readlinkat(self, mu, dfd, path, buf, bufsz):
        path_utf8 = memory_helpers.read_utf8(mu, path)
        logging.debug("%x %s %x %r"%(dfd, path_utf8, buf, bufsz))
        path_utf8 =  self.__dirfd_2_path(dfd, path_utf8)
        if (path_utf8 == None):
            return -1
        #
        pobj = self.__pcb
        pid = pobj.get_pid()
        path_std_utf = path_utf8.replace(str(pid), "self")
        fd_base = "/proc/self/fd/"
        if (path_std_utf.startswith(fd_base)):
            fd_str = os.path.basename(path_std_utf)
            fd = int(fd_str)
            detail = self.__pcb.get_fd_detail(fd)
            name = detail.name
            n = len(name)
            if (n <= bufsz):
                memory_helpers.write_utf8(mu, buf, name)
                return 0
            #
            else:
                raise RuntimeError("buffer overflow!!!")
            #
        else:
            raise NotImplementedError()
        #
        return -1
    #
    
    def _faccessat(self, mu, dirfd, pathname_ptr, mode, flag):
        filename = memory_helpers.read_utf8(mu, pathname_ptr)
        logging.debug("faccessat filename:[%s]"%filename)
        filename = self.__dirfd_2_path(dirfd, filename)
        if (filename == None):
            return -1
        #
        name_in_host = self.__translate_path(filename)
        if (os.access(name_in_host, mode)):
            return 0
        else:
            logging.debug("faccessat filename:[%s] not exist"%filename)
            return -1
        #
    #

#
