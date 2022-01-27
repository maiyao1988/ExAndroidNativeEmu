import calendar
import logging
import math
import os
import time
import sys
import ctypes
import socket
from random import randint

from unicorn import Uc
from unicorn.arm_const import *

from ..const.android import *
from ..const.linux import *
from ..const import emu_const
from.syscall_handlers import SyscallHandlers
from ..utils import memory_helpers
from .. import config
from .. import pcb
from ..utils import debug_utils, misc_utils

OVERRIDE_TIMEOFDAY = False
OVERRIDE_TIMEOFDAY_SEC = 0
OVERRIDE_TIMEOFDAY_USEC = 0

OVERRIDE_CLOCK = False
OVERRIDE_CLOCK_TIME = 0

class SyscallHooks:

    #system call table
    #https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#arm-32_bit_EABI
    """
    :type mu Uc
    :type syscall_handler SyscallHandlers
    """
    def __init__(self, emu, cfg, syscall_handler):
        self.__emu = emu
        self.__ptr_sz = emu.get_ptr_size()
        self._syscall_handler = syscall_handler
        if (self.__emu.get_arch() == emu_const.ARCH_ARM32):
            self._syscall_handler.set_handler(0x1, "exit", 1, self.__exit)
            self._syscall_handler.set_handler(0x2, "fork", 0, self.__fork)
            self._syscall_handler.set_handler(0x0B, "execve", 3, self.__execve)
            self._syscall_handler.set_handler(0x14, "getpid", 0, self._getpid)
            self._syscall_handler.set_handler(0x18, "getuid", 0, self._get_uid)
            self._syscall_handler.set_handler(0x1A, "ptrace", 4, self.__ptrace)
            self._syscall_handler.set_handler(0x25, "kill", 2, self.__kill)
            self._syscall_handler.set_handler(0x2A, "pipe", 1, self.__pipe)
            self._syscall_handler.set_handler(0x43, "sigaction", 3, self._handle_sigaction)
            self._syscall_handler.set_handler(0x4E, "gettimeofday", 2, self._handle_gettimeofday)
            self._syscall_handler.set_handler(0x72, "wait4", 4, self.__wait4)
            self._syscall_handler.set_handler(0x74, "sysinfo", 1, self.__sysinfo)
            self._syscall_handler.set_handler(0x78, "clone", 5, self.__clone)
            self._syscall_handler.set_handler(0x7A, "uname", 1, self.__uname)
            self._syscall_handler.set_handler(0x7E, "sigprocmask", 3, self._handle_sigprocmask)
            self._syscall_handler.set_handler(0xAC, "prctl", 5, self._handle_prctl)
            self._syscall_handler.set_handler(0xAE, "rt_sigaction", 4, self._rt_sigaction)
            self._syscall_handler.set_handler(0xAF, "rt_sigprocmask", 4, self._handle_rt_sigprocmask)
            self._syscall_handler.set_handler(0xBA, "sigaltstack", 2, self.__sigaltstack)
            self._syscall_handler.set_handler(0xBE, "vfork", 0, self.__vfork)
            self._syscall_handler.set_handler(0xC7, "getuid32", 0, self._get_uid)
            self._syscall_handler.set_handler(0xDA, "set_tid_address", 1, self.__set_tid_address)
            self._syscall_handler.set_handler(0xE0, "gettid", 0, self._gettid)
            self._syscall_handler.set_handler(0xF0, "futex", 6, self._handle_futex)
            self._syscall_handler.set_handler(0x10c, "tgkill", 3, self._handle_tgkill)
            self._syscall_handler.set_handler(0x107, "clock_gettime", 2, self._handle_clock_gettime)
            self._syscall_handler.set_handler(0x119, "socket", 3, self._socket)
            self._syscall_handler.set_handler(0x11a, "bind", 3, self._bind)
            self._syscall_handler.set_handler(0x11b, "connect", 3, self._connect)
            self._syscall_handler.set_handler(0x126, "setsockopt", 5, self._setsockopt)
            self._syscall_handler.set_handler(0x159, "getcpu", 3, self._getcpu)
            self._syscall_handler.set_handler(0x166, "dup3", 3, self.__dup3)
            self._syscall_handler.set_handler(0x167, "pipe2", 2, self.__pipe2)
            self._syscall_handler.set_handler(0x178, "process_vm_readv", 6, self.__process_vm_readv)
            self._syscall_handler.set_handler(0x180, "getrandom", 3, self._getrandom)
            self._syscall_handler.set_handler(0xf0002, "ARM_cacheflush", 0, self._ARM_cacheflush)
            self._syscall_handler.set_handler(0xf0005, "ARM_set_tls", 1, self._ARM_set_tls)

            self._syscall_handler.set_handler(0xa2, "nanosleep", 2, self._nanosleep)
        else:
            #arm64
            self._syscall_handler.set_handler(0x5D, "exit", 1, self.__exit)
            #arm64没有fork，统一采用clone调用
            self._syscall_handler.set_handler(0xDD, "execve", 3, self.__execve)
            self._syscall_handler.set_handler(0xAC, "getpid", 0, self._getpid)
            self._syscall_handler.set_handler(0xAE, "getuid", 0, self._get_uid)
            self._syscall_handler.set_handler(0x75, "ptrace", 4, self.__ptrace)
            self._syscall_handler.set_handler(0x81, "kill", 2, self.__kill)
            #arm64没有pipe系统调用
            #arm64没sigaction系统调用
            self._syscall_handler.set_handler(0xA9, "gettimeofday", 2, self._handle_gettimeofday)
            self._syscall_handler.set_handler(0x104, "wait4", 4, self.__wait4)
            self._syscall_handler.set_handler(0xB3, "sysinfo", 1, self.__sysinfo)
            self._syscall_handler.set_handler(0xDC, "clone", 5, self.__clone)
            self._syscall_handler.set_handler(0xA0, "uname", 1, self.__uname)
            #no sigprocmask
            self._syscall_handler.set_handler(0xA7, "prctl", 5, self._handle_prctl)
            self._syscall_handler.set_handler(0x86, "rt_sigaction", 4, self._rt_sigaction)
            self._syscall_handler.set_handler(0x87, "rt_sigprocmask", 4, self._handle_rt_sigprocmask)
            self._syscall_handler.set_handler(0x84, "sigaltstack", 2, self.__sigaltstack)
            #no vfork
            #no getuid32
            self._syscall_handler.set_handler(0xB2, "gettid", 0, self._gettid)
            self._syscall_handler.set_handler(0x62, "futex", 6, self._handle_futex)
            self._syscall_handler.set_handler(0x83, "tgkill", 3, self._handle_tgkill)
            self._syscall_handler.set_handler(0x71, "clock_gettime", 2, self._handle_clock_gettime)
            self._syscall_handler.set_handler(0xC6, "socket", 3, self._socket)
            self._syscall_handler.set_handler(0xC8, "bind", 3, self._bind)
            self._syscall_handler.set_handler(0xCB, "connect", 3, self._connect)
            self._syscall_handler.set_handler(0xD0, "setsockopt", 5, self._setsockopt)
            self._syscall_handler.set_handler(0xA8, "getcpu", 3, self._getcpu)
            self._syscall_handler.set_handler(0x18, "dup3", 3, self.__dup3)
            self._syscall_handler.set_handler(0x3B, "pipe2", 2, self.__pipe2)
            self._syscall_handler.set_handler(0x10E, "process_vm_readv", 6, self.__process_vm_readv)
            self._syscall_handler.set_handler(0x116, "getrandom", 3, self._getrandom)
            #no ARM_cacheflush
            self._syscall_handler.set_handler(0x65, "nanosleep", 2, self._nanosleep)
        #
        self._clock_start = time.time()
        self._clock_offset = randint(50000, 100000)
        self._sig_maps = {}
        self.__pcb = self.__emu.get_pcb()
        self.__cfg = cfg
        self._process_name = cfg.get("pkg_name") #"ChromiumNet10"
        self.__tid_2_tid_addr = {}
    #

    def __do_fork(self, mu):
        logging.debug("fork called")
        r = os.fork()
        if (r == 0):
            pass
            #实测这样改没效果
            #logging.basicConfig(level=logging.DEBUG, format='%(process)d - %(asctime)s - %(levelname)s - %(message)s', stream=sys.stdout)
        #
        else:
            logging.debug("-----here is parent process child pid=%d"%r)
        #
        return r
    #

    def __exit(self, mu, err_code):
        sch = self.__emu.get_schduler()
        cur_tid = sch.get_current_tid()
        if (cur_tid in self.__tid_2_tid_addr):
            #CLONE_CHILD_CLEARTID 语义，退出时候唤醒线程对应的tid_addr对应的futex
            #这是线程退出自动清理futex的关键
            #见https://man7.org/linux/man-pages/man2/clone.2.html  CLONE_CHILD_CLEARTID描述
            tid_addr_futex = self.__tid_2_tid_addr[cur_tid]
            sch.futex_wake(tid_addr_futex)
            mu.mem_write(tid_addr_futex, int(0).to_bytes(4, byteorder='little'))
            self.__tid_2_tid_addr.pop(cur_tid)
        #
        #TODO use err_code
        sch.exit_current_task()
        return 0
    #

    def __fork(self, mu):
        return self.__do_fork(mu)
    #

    def __execve(self, mu, filename_ptr, argv_ptr, envp_ptr):
        filename =memory_helpers.read_utf8(mu, filename_ptr)
        ptr = argv_ptr
        params = []
        logging.debug("execve run")

        while True:
            off = memory_helpers.read_ptr_sz(mu, ptr, self.__ptr_sz)
            param = memory_helpers.read_utf8(mu, off)
            if (len(param) == 0):
                break
            params.append(param)
            ptr += self.__emu.get_ptr_size()
        #
        logging.warning("execve %s %r"%(filename, params))
        cmd = " ".join(params)

        pkg_name = self.__cfg.get("pkg_name")
        pm = "pm path %s"%(pkg_name,)
        if(cmd.find(pm) > -1):
            output = "package:/data/app/%s-1.apk"%pkg_name
            logging.debug("write to stdout [%s]"%output)
            os.write(1, output.encode("utf-8"))
            sys.exit(0)
        #
        elif(cmd.find('wm density') > -1):
            output = "Physical density: 420"
            logging.info("write to stdout [%s]" % output)
            os.write(1, output.encode("utf-8"))
            sys.exit(0)
        elif(cmd.find('wm size') > -1):
            output = "Physical size: 1080x1920"
            logging.info("write to stdout [%s]" % output)
            os.write(1, output.encode("utf-8"))
            sys.exit(0)
        elif (cmd.find('adbd') > -1):
            output = ""
            logging.info("write to stdout [%s]" % output)
            os.write(1, output.encode("utf-8"))
            sys.exit(0)

        else:
            raise NotImplementedError()
        #
    #

    def _getpid(self, mu):
        return self.__pcb.get_pid()
    #

    def __ptrace(self, mu, request, pid, addr, data):
        logging.warning("skip syscall ptrace request [%d] pid [0x%x] addr [0x%08X] data [0x%08X]"%(request, pid, addr, data))
        return 0
    #

    def __kill(self, mu, pid, sig):
        logging.warning("kill is call pid=0x%x sig=%d"%(pid, sig))
        if (pid == self._getpid(mu)):
            logging.error("process 0x%x is killing self!!! maybe encounter anti-debug!!!"%pid)
            sys.exit(-10)
        #
    #

    def __pipe_common(self, mu, files_ptr, flags):
        #logging.warning("skip syscall pipe files [0x%08X]"%files_ptr)
        if (hasattr(os, "pipe2")):
            ps = os.pipe2(flags)
        else:
            logging.warning("pipe2 not support use pipe")
            ps = os.pipe()
        #
        logging.debug("pipe return %r"%(ps,))
        self.__pcb.add_fd("[pipe_r]", "[pipe_r]", ps[0])
        self.__pcb.add_fd("[pipe_w]", "[pipe_w]", ps[1])
        #files_ptr 无论32还是64 都是个int数组，因此写4没有问题
        mu.mem_write(files_ptr, int(ps[0]).to_bytes(4, byteorder='little'))
        mu.mem_write(files_ptr+4, int(ps[1]).to_bytes(4, byteorder='little'))
        return 0
    #

    def __pipe(self, mu, files_ptr):
        return self.__pipe_common(mu, files_ptr, 0)
    #
    
    def _handle_sigaction(self, mu, sig, act, oact):
        '''
        struct sigaction {
            union {
                void     (*sa_handler)(int);
                void     (*sa_sigaction)(int, siginfo_t *, void *);
            },
            sigset_t   sa_mask;
            int        sa_flags;
            void     (*sa_restorer)(void);
        };
        '''
        act_off = act
        sa_handler = memory_helpers.read_ptr_sz(mu, act_off, self.__ptr_sz)
        act_off+=self.__ptr_sz
        sa_mask = memory_helpers.read_ptr_sz(mu, act_off, self.__ptr_sz)
        act_off+=self.__ptr_sz
        sa_flag = memory_helpers.read_ptr_sz(mu, act_off, self.__ptr_sz)
        act_off+=self.__ptr_sz
        sa_restorer = memory_helpers.read_ptr_sz(mu, act_off, self.__ptr_sz)

        logging.debug("sa_handler [0x%08X] sa_mask [0x%08X] sa_flag [0x%08X] sa_restorer [0x%08X]"%(sa_handler, sa_mask, sa_flag, sa_restorer))
        self._sig_maps[sig] = (sa_handler, sa_mask, sa_flag, sa_restorer)
        return 0
    #


    def _rt_sigaction(self, mu, sig, act, oact, sigsetsize):
        '''
        struct sigaction {
            union {
                void     (*sa_handler)(int);
                void     (*sa_sigaction)(int, siginfo_t *, void *);
            },
            sigset_t   sa_mask;
            int        sa_flags;
            void     (*sa_restorer)(void);
        };
        '''
        act_off = act
        sa_handler = memory_helpers.read_ptr_sz(mu, act_off, self.__ptr_sz)
        act_off+=self.__ptr_sz
        #sigsetsize是sa_mask的大小，64位下一般位8，see https://man7.org/linux/man-pages/man2/sigaction.2.html
        sa_mask = memory_helpers.read_ptr_sz(mu, act_off, sigsetsize)
        act_off+=sigsetsize
        sa_flag = memory_helpers.read_ptr_sz(mu, act_off, self.__ptr_sz)
        act_off+=self.__ptr_sz
        sa_restorer = memory_helpers.read_ptr_sz(mu, act_off, self.__ptr_sz)

        logging.debug("sa_handler [0x%08X] sa_mask [0x%08X] sa_flag [0x%08X] sa_restorer [0x%08X]"%(sa_handler, sa_mask, sa_flag, sa_restorer))
        self._sig_maps[sig] = (sa_handler, sa_mask, sa_flag, sa_restorer)
        return 0
    #

    def _gettid(self, mu):
        sch = self.__emu.get_schduler()
        return sch.get_current_tid()
    #

    def _setsockopt(self, mu, fd, level, optname, optval, optlen):
        logging.warning("_setsockopt not implement skip")
        return 0
    #

    def _getcpu(self, mu, _cpu, node, cache):
        if _cpu != 0:
            #unsigned *指针，写4没问题
            mu.mem_write(_cpu, int(1).to_bytes(4, byteorder='little'))
        return 0

    def _handle_gettimeofday(self, uc, tv, tz):
        """
        If either tv or tz is NULL, the corresponding structure is not set or returned.
        """

        if tv != 0:
            ptr_sz = self.__emu.get_ptr_size()
            if OVERRIDE_TIMEOFDAY:
                uc.mem_write(tv + 0, int(OVERRIDE_TIMEOFDAY_SEC).to_bytes(ptr_sz, byteorder='little'))
                uc.mem_write(tv + ptr_sz, int(OVERRIDE_TIMEOFDAY_USEC).to_bytes(ptr_sz, byteorder='little'))
            else:
                timestamp = time.time()
                (usec, sec) = math.modf(timestamp)
                usec = abs(int(usec * 100000))

                uc.mem_write(tv + 0, int(sec).to_bytes(ptr_sz, byteorder='little'))
                uc.mem_write(tv + ptr_sz, int(usec).to_bytes(ptr_sz, byteorder='little'))

        if tz != 0:
            #timezone结构体不64还是32都是两个4字节成员
            uc.mem_write(tz + 0, int(-120).to_bytes(4, byteorder='little'))  # minuteswest -(+GMT_HOURS) * 60
            uc.mem_write(tz + 4, int().to_bytes(4, byteorder='little'))  # dsttime

        return 0
    #

    def __wait4(self, mu, pid, wstatus, options, ru):
        assert ru==0
        #return pid
        logging.debug("syscall wait4 pid %d"%pid)
        t = os.wait4(pid, options)
        logging.debug("wait4 return %r"%(t,))
        #wstatus 只是一个int指针，固定是4
        mu.mem_write(wstatus, int(t[1]).to_bytes(4, "little"))
        return t[0]
    #
    
    def __sysinfo(self, mu, info_ptr):
        '''
        si = {sysinfo} 
        uptime = {__kernel_long_t} 91942
        loads = {__kernel_ulong_t [3]} 
        [0] = {__kernel_ulong_t} 503328
        [1] = {__kernel_ulong_t} 504576
        [2] = {__kernel_ulong_t} 537280
        totalram = {__kernel_ulong_t} 1945137152
        freeram = {__kernel_ulong_t} 47845376
        sharedram = {__kernel_ulong_t} 0
        bufferram = {__kernel_ulong_t} 169373696
        totalswap = {__kernel_ulong_t} 0
        freeswap = {__kernel_ulong_t} 0
        procs = {__u16} 1297
        pad = {__u16} 0
        totalhigh = {__kernel_ulong_t} 1185939456
        freehigh = {__kernel_ulong_t} 1863680
        mem_unit = {__u32} 1
        f = 0 char[8]
        '''
        uptime = int(self._clock_offset + time.time() - self._clock_start)
        if self.__emu.get_arch() == emu_const.ARCH_ARM32:
            mu.mem_write(info_ptr + 0, int(uptime).to_bytes(4, byteorder='little'))
            mu.mem_write(info_ptr + 4, int(503328).to_bytes(4, byteorder='little'))
            mu.mem_write(info_ptr + 8, int(504576).to_bytes(4, byteorder='little'))
            mu.mem_write(info_ptr + 12, int(537280).to_bytes(4, byteorder='little'))
            mu.mem_write(info_ptr + 16, int(1945137152).to_bytes(4, byteorder='little'))
            mu.mem_write(info_ptr + 20, int(47845376).to_bytes(4, byteorder='little'))
            mu.mem_write(info_ptr + 24, int(0).to_bytes(4, byteorder='little'))
            mu.mem_write(info_ptr + 28, int(169373696).to_bytes(4, byteorder='little'))
            mu.mem_write(info_ptr + 32, int(0).to_bytes(4, byteorder='little'))
            mu.mem_write(info_ptr + 36, int(0).to_bytes(4, byteorder='little'))
            mu.mem_write(info_ptr + 40, int(1297).to_bytes(2, byteorder='little'))
            mu.mem_write(info_ptr + 42, int(0).to_bytes(2, byteorder='little'))
            mu.mem_write(info_ptr + 44, int(1185939456).to_bytes(4, byteorder='little'))
            mu.mem_write(info_ptr + 48, int(1863680).to_bytes(4, byteorder='little'))
            mu.mem_write(info_ptr + 52, int(1).to_bytes(4, byteorder='little'))
            mu.mem_write(info_ptr + 56, int(0).to_bytes(8, byteorder='little'))
            #sz 64
        else:
            #arm64
            mu.mem_write(info_ptr + 0, int(uptime).to_bytes(8, byteorder='little'))
            mu.mem_write(info_ptr + 8, int(503328).to_bytes(8, byteorder='little'))
            mu.mem_write(info_ptr + 16, int(504576).to_bytes(8, byteorder='little'))
            mu.mem_write(info_ptr + 24, int(537280).to_bytes(8, byteorder='little'))
            mu.mem_write(info_ptr + 32, int(1945137152).to_bytes(8, byteorder='little'))
            mu.mem_write(info_ptr + 40, int(47845376).to_bytes(8, byteorder='little'))
            mu.mem_write(info_ptr + 48, int(0).to_bytes(8, byteorder='little'))
            mu.mem_write(info_ptr + 56, int(169373696).to_bytes(8, byteorder='little'))
            mu.mem_write(info_ptr + 64, int(0).to_bytes(8, byteorder='little'))
            mu.mem_write(info_ptr + 72, int(0).to_bytes(8, byteorder='little'))
            mu.mem_write(info_ptr + 80, int(1297).to_bytes(2, byteorder='little'))
            mu.mem_write(info_ptr + 82, int(0).to_bytes(6, byteorder='little')) #pading

            mu.mem_write(info_ptr + 88, int(0).to_bytes(8, byteorder='little'))
            mu.mem_write(info_ptr + 96, int(0).to_bytes(8, byteorder='little'))
            mu.mem_write(info_ptr + 104, int(1).to_bytes(4, byteorder='little'))
            mu.mem_write(info_ptr + 108, int(0).to_bytes(4, byteorder='little'))
            #sz 112
        #
        logging.warning("syscall sysinfo buf 0x%08X return fixed value"%(info_ptr))
        return 0
    #

    def __clone(self, mu, flags, child_stack, parent_tid, new_tls, child_tid):
        CLONE_FILES = 0x00000400
        CLONE_FS = 0x00000200
        CLONE_SIGHAND = 0x00000800
        CLONE_THREAD = 0x00010000
        CLONE_CHILD_SETTID = 0x01000000
        CLONE_CHILD_CLEARTID = 0x00200000
        CLONE_VM = 0x00000100
        CLONE_VFORK = 0x00004000
        CLONE_SYSVSEM = 0x00040000
        CLONE_SETTLS = 0x00080000
        CLONE_PARENT_SETTID = 0x00100000

        SIGCHLD = 17
        vfork_flags = CLONE_VM|CLONE_VFORK|SIGCHLD
        fork_flags = CLONE_CHILD_SETTID|CLONE_CHILD_CLEARTID|SIGCHLD

        #thread clone flags
        thread_flags = CLONE_FILES | CLONE_FS | CLONE_VM | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM
        #6.0 clone thread CLONE_FILES| CLONE_FS | CLONE_VM| CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM | CLONE_SETTLS | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID
        if (flags & fork_flags == fork_flags or 
            flags & vfork_flags == vfork_flags):
            #fork or vfork
            #0x01200011 is fork flag
            #clone(0x01200011, 0x00000000, 0x00000000, 0x00000000, 0x00000008)
            logging.warning("syscall clone do fork...")
            return self.__do_fork(mu)
        #
        elif(flags & thread_flags == thread_flags):
            logging.warning("syscall clone do thread clone...")
            #clone一定要成功， 4.4 的libc有bug，当clone失败之后会释放一个锁，而锁的内存在child_stack中，而他逻辑先释放了stack再unlock锁，必蹦，之所以不出问题的原因是在真机上clone不会失败，这里注意
            sch = self.__emu.get_schduler()
            #父线程调用clone，返回子线程tid
            tls_ptr = 0
            if (flags & (CLONE_SETTLS|CLONE_CHILD_SETTID|CLONE_CHILD_CLEARTID) != 0):
                tls_ptr = new_tls
            tid = sch.add_sub_task(child_stack, tls_ptr)
            logging.debug("clone thread call in parent thread return child thread tid [%d] child_stack [0x%08X] tls_ptr [0x%08X]"%(tid, child_stack, tls_ptr))
            #let the child thread run first
            sch.yield_task()
            #6.0的libc使用这几个参数设置tid，而不使用返回值，这跟4.4的libc实现不同，两个都要兼容
            if (flags & (CLONE_PARENT_SETTID|CLONE_SETTLS|CLONE_CHILD_SETTID|CLONE_CHILD_CLEARTID) != 0):
                mu.mem_write(parent_tid, tid.to_bytes(4, byteorder='little'))
            #
            if (flags & (CLONE_CHILD_SETTID|CLONE_CHILD_CLEARTID) != 0):
                mu.mem_write(child_tid, tid.to_bytes(4, byteorder='little'))
            #
            if (flags & CLONE_CHILD_CLEARTID):
                #save the child_tid ptr
                self.__tid_2_tid_addr[tid] = child_tid
            #
            
            return tid
        #
        
        #logging.warning("syscall clone skip.")
        raise NotImplementedError("clone flags 0x%08X no suppport"%flags)
        return -1
    #

    def _handle_prctl(self, mu, option, arg2, arg3, arg4, arg5):
        """
        int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
        See:
        - https://linux.die.net/man/2/prctl
        - https://github.com/torvalds/linux/blob/master/include/uapi/linux/prctl.h

        For PR_SET_VMA:
        - https://android.googlesource.com/platform/bionic/+/263325d/libc/include/sys/prctl.h
        - https://sourceforge.net/p/strace/mailman/message/34329772/
        """
        get_sets = set([PR_GET_DUMPABLE, PR_GET_UNALIGN, PR_GET_FPEMU, PR_GET_FPEXC, PR_GET_TIMING, PR_GET_NAME])
        if (option in get_sets and arg2 == 0):
            #传入非法指针，linux内核不会出发crash而只会返回失败
            logging.warning("prctl getter but buffer is 0")
            return -1
        #

        if option == PR_SET_VMA:
            # arg5 contains ptr to a name.
            return 0
        elif option == PR_SET_DUMPABLE:
            return 0
        elif option == PR_GET_NAME:
            memory_helpers.write_utf8(mu, arg2, self._process_name)
            return 0
        elif option == PR_GET_DUMPABLE:
            mu.mem_write(arg2, int(0).to_bytes(self.__ptr_sz, byteorder='little'))
            return 0
        elif option == PR_SET_NAME:
            self._process_name = memory_helpers.read_utf8(mu, arg2)
            return 0
        else:
            raise NotImplementedError("Unsupported prctl option %d (0x%x)" % (option, option))
        #
    #
    def __uname(self, mu, buf):
        #    uts.sysname = Linux
        #    uts.nodename = localhost
        #    uts.release = 3.10.73-gf97f123
        #    uts.version = #1 SMP PREEMPT Mon Nov 2 20:10:58 UTC 2015
        #    uts.machine = armv8l
        #    uts.domainname = localdomain

        memory_helpers.write_utf8(mu, buf + 0, "Linux")
        memory_helpers.write_utf8(mu, buf + 65, "localhost")
        memory_helpers.write_utf8(mu, buf + 130, "3.10.73-gf97f123")
        memory_helpers.write_utf8(mu, buf + 195, "#1 SMP PREEMPT Mon Nov 2 20:10:58 UTC 2015")
        memory_helpers.write_utf8(mu, buf + 260, "armv8l")
        memory_helpers.write_utf8(mu, buf + 325, "localdomain")

        return 0
    #

    def _handle_sigprocmask(self, mu, how, set, oset):
        return 0
    #

    def _handle_rt_sigprocmask(self, mu, how, set, oset, sigsetsize):
        return 0
    #

    def __sigaltstack(self, mu, uss, ouss):
        #TODO implment
        return 0
    #

    def __vfork(self, mu):
        return self.__do_fork(mu)
    #

    def _get_uid(self, mu):
        uid = self.__cfg.get("uid")
        return uid
    #

    def __set_tid_address(self, mu, tidptr):
        sch = self.__emu.get_schduler
        tid = sch.get_current_tid()
        if (not tidptr):
            self.__tid_2_tid_addr.pop(tid)
        else:
            self.__tid_2_tid_addr[tid] = tidptr
        return tid
    #

    def _handle_futex(self, mu, uaddr, op, val, timeout_ptr, uaddr2, val3):
        #uaddr 是u32指针，所以指向的大小恒为4
        v = mu.mem_read(uaddr, 4)
        v = int.from_bytes(v, byteorder='little', signed=False)
        """
        See: https://linux.die.net/man/2/futex
        """
        cmd = op & FUTEX_CMD_MASK
        sch = self.__emu.get_schduler()
        if cmd == FUTEX_WAIT or cmd == FUTEX_WAIT_BITSET:
            #TODO implement timeout
            logging.info("futext_wait call op=0x%08X uaddr=0x%08X *uaddr=0x%08X val=0x%08X timeout=0x%08X"%(op, uaddr, v, val, timeout_ptr))
            if v == val:
                timeout = -1
                if (timeout_ptr):
                    req_tv_sec = memory_helpers.read_ptr_sz(mu, timeout_ptr, self.__ptr_sz)
                    req_tv_nsec = memory_helpers.read_ptr_sz(mu, timeout_ptr + self.__ptr_sz, self.__ptr_sz)
                    ms = req_tv_sec * 1000 + req_tv_nsec / 1000000
                    timeout = ms
                    #TODO 这里timeout返回-1和ETIMEOUT，不能在这里返回，需要在调度器判断是否timeout而写r0和set_errno，暂时没实现，写死返回0
                    logging.warning("futex timeout %d ms is set, the return value is 0 not matter if it expired!!!"%ms)
                #
                sch.futex_wait(uaddr, timeout)
            #
            return 0
        elif cmd == FUTEX_WAKE or cmd == FUTEX_WAKE_BITSET:
            logging.debug("futex_wake call op=0x%08X uaddr=0x%08X val=0x%08X"%(op, uaddr, val))
            assert val <= 0x7fffffff, "futex wake val=0x%08X bigger than int max!!!"%val
            nwake = 0
            for i in range(0, val):
                wake_ok = sch.futex_wake(uaddr)
                if not wake_ok:
                    break
                #
                nwake = nwake+1
            #
            if nwake > 0:
                #交出执行权，这里只是为了适应某些so例如某dy，死循环等待的问题，这是由于uc对timeout的支持有bug,暂时无法支持时间片调度
                sch.yield_task()
            #
            return nwake
        elif cmd == FUTEX_FD:
            raise NotImplementedError()
        elif cmd == FUTEX_REQUEUE:
            raise NotImplementedError()
        elif cmd == FUTEX_CMP_REQUEUE:
            raise NotImplementedError()
        else:
            raise NotImplementedError()
        return 0
    #

    def _handle_tgkill(self, mu, tgid, tid, sig):
        if (tgid ==  self._getpid(mu) and sig == 6):
            raise RuntimeError("tgkill abort self....")
            return 0
        #
        return 0
        if (tgid == self._getpid(mu) and tid == self._gettid(mu)):
            if (sig in self._sig_maps):

                sigact = self._sig_maps[sig]
                addr = sigact[0]
                #TODO implement signal handling
                return 0
            #
        #
        raise NotImplementedError()
        return 0

    def _handle_clock_gettime(self, mu, clk_id, tp_ptr):
        """
        The functions clock_gettime() retrieve the time of the specified clock clk_id.

        The clk_id argument is the identifier of the particular clock on which to act. A clock may be system-wide and
        hence visible for all processes, or per-process if it measures time only within a single process.

        clock_gettime(), clock_settime() and clock_getres() return 0 for success, or -1 for failure (in which case
        errno is set appropriately).
        """

        if clk_id == CLOCK_REALTIME:
            # Its time represents seconds and nanoseconds since the Epoch.
            clock_real = calendar.timegm(time.gmtime())

            mu.mem_write(tp_ptr + 0, int(clock_real).to_bytes(self.__ptr_sz, byteorder='little'))
            mu.mem_write(tp_ptr + self.__ptr_sz, int(0).to_bytes(self.__ptr_sz, byteorder='little'))
            return 0
        elif clk_id == CLOCK_MONOTONIC or clk_id == CLOCK_MONOTONIC_COARSE:
            if OVERRIDE_CLOCK:
                mu.mem_write(tp_ptr + 0, int(OVERRIDE_CLOCK_TIME).to_bytes(self.__ptr_sz, byteorder='little'))
                mu.mem_write(tp_ptr + self.__ptr_sz, int(0).to_bytes(self.__ptr_sz, byteorder='little'))
            else:
                clock_add = time.time() - self._clock_start  # Seconds passed since clock_start was set.

                mu.mem_write(tp_ptr + 0, int(self._clock_start + clock_add).to_bytes(self.__ptr_sz, byteorder='little'))
                mu.mem_write(tp_ptr + self.__ptr_sz, int(0).to_bytes(self.__ptr_sz, byteorder='little'))
            return 0
        else:
            raise NotImplementedError("Unsupported clk_id: %d (%x)" % (clk_id, clk_id))

    def _socket(self, mu, family, type_in, protocol):
        if (family == 16):
            logging.warning("family 16 not support")
            return -1
        #
        if (protocol == 0):
            logging.warning("protocol 0 not support")
            return -1
        #
        #print(family)
        s = socket.socket(family, type_in, protocol)
        socket_id = s.fileno()
        self.__pcb.add_fd("[socket]", "[socket]", socket_id)
        return socket_id
    #

    def _bind(self, mu, fd, addr, addr_len):

        # The struct is confusing..
        addr = mu.mem_read(addr + 3, addr_len - 3).decode(encoding="utf-8")

        logging.info('Binding socket to ://%s' % addr)
        raise NotImplementedError()
        return 0

    def _connect(self, mu, fd, addr, addr_len):
        """
        If the connection or binding succeeds, zero is returned.
        On error, -1 is returned, and errno is set appropriately.
        """
        #hexdump.hexdump(mu.mem_read(addr, addr_len))
        
        # return 0
        return -1
        # raise NotImplementedError()
    #
    
    def __dup3(self, mu, oldfd, newfd, flags):
        assert flags == 0, "dup3 flag not support now"
        old_detail = self.__pcb.get_fd_detail(oldfd)
        os.dup2(oldfd, newfd)
        self.__pcb.add_fd(old_detail.name, old_detail.name_in_system, newfd)
        return 0
    #

    def __pipe2(self, mu, files_ptr, flags):
        return self.__pipe_common(mu, files_ptr, flags)
    #

    def _getrandom(self, mu, buf, count, flags):
        mu.mem_write(buf, b"\x01" * count)
        return count

    def __process_vm_readv(self, mu, pid, local_iov, liovcnt, remote_iov, riovcnt, flag):
        '''
        struct iovec {
            void  *iov_base;    /* Starting address */
            size_t iov_len;     /* Number of bytes to transfer */
        };
        '''
        if (pid != self._getpid(mu)):
            raise NotImplementedError("__process_vm_readv return other process not support...")
        off_r = remote_iov
        b = b''
        for i in range(0, riovcnt):
            rbase = memory_helpers.read_ptr_sz(mu, off_r, self.__ptr_sz)
            iov_len = memory_helpers.read_ptr_sz(mu, off_r+self.__ptr_sz, self.__ptr_sz)
            tmp = memory_helpers.read_byte_array(mu, rbase, iov_len)
            b+=tmp
            off_r+=2*self.__ptr_sz
        #
        off_l = local_iov
        has_read = 0
        for j in range(0, liovcnt):
            lbase = memory_helpers.read_ptr_sz(mu, off_l, self.__ptr_sz)
            liov_len = memory_helpers.read_ptr_sz(mu, off_l+self.__ptr_sz, self.__ptr_sz)
            tmp = b[has_read:liov_len]
            mu.mem_write(lbase, tmp)
            has_read += len(tmp)
            off_l += 2*self.__ptr_sz
        #
        #print(b)
        return has_read
    #

    def _ARM_cacheflush(self, mu):
        logging.warning("syscall _ARM_cacheflush skip.")
        return 0
    #

    def _ARM_set_tls(self, mu, tls_ptr):
        assert self.__emu.get_arch() == emu_const.ARCH_ARM32, "error only arm32 has _ARM_set_tls syscall!!!"
        self.__emu.mu.reg_write(UC_ARM_REG_C13_C0_3, tls_ptr)
    #
    
    def _nanosleep(self, mu, req, rem):
        '''
        int nanosleep(const struct timespec *req,struct timespec *rem);
        struct timespec{
              time_t  tv_sec;         /* seconds */
              long    tv_nsec;        /* nanoseconds */
        };
        '''
        req_tv_sec = memory_helpers.read_ptr_sz(mu, req, self.__ptr_sz)
        req_tv_nsec = memory_helpers.read_ptr_sz(mu, req + self.__ptr_sz, self.__ptr_sz)
        ms = req_tv_sec * 1000 + req_tv_nsec / 1000000
        logging.debug("nanosleep sleep %.3f ms"%ms)
        sch = self.__emu.get_schduler()
        sch.sleep(ms)
        return 0
    #
#
