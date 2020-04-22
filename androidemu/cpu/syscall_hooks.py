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
from.syscall_handlers import SyscallHandlers
from ..utils import memory_helpers
from .. import config
from .. import pcb
from ..utils import debug_utils

OVERRIDE_TIMEOFDAY = False
OVERRIDE_TIMEOFDAY_SEC = 0
OVERRIDE_TIMEOFDAY_USEC = 0

OVERRIDE_CLOCK = False
OVERRIDE_CLOCK_TIME = 0

logger = logging.getLogger(__name__)


class SyscallHooks:

    #system call table
    #https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#arm-32_bit_EABI
    """
    :type mu Uc
    :type syscall_handler SyscallHandlers
    """
    def __init__(self, mu, syscall_handler):
        self._mu = mu
 
        self._syscall_handler = syscall_handler
        self._syscall_handler.set_handler(0x2, "fork", 0, self.__fork)
        self._syscall_handler.set_handler(0x0B, "execve", 3, self.__execve)
        self._syscall_handler.set_handler(0x14, "getpid", 0, self._getpid)
        self._syscall_handler.set_handler(0x1A, "ptrace", 4, self.__ptrace)
        self._syscall_handler.set_handler(0x25, "kill", 2, self.__kill)
        self._syscall_handler.set_handler(0x2A, "pipe", 1, self.__pipe)
        self._syscall_handler.set_handler(0x43, "sigaction", 3, self._handle_sigaction)
        self._syscall_handler.set_handler(0x4E, "gettimeofday", 2, self._handle_gettimeofday)
        self._syscall_handler.set_handler(0x72, "wait4", 4, self.__wait4)
        self._syscall_handler.set_handler(0x74, "sysinfo", 1, self.__sysinfo)
        self._syscall_handler.set_handler(0x78, "clone", 5, self.__clone)
        self._syscall_handler.set_handler(0xAC, "prctl", 5, self._handle_prctl)
        self._syscall_handler.set_handler(0xAF, "sigprocmask", 3, self._handle_sigprocmask)
        self._syscall_handler.set_handler(0xBE, "vfork", 0, self.__vfork)
        self._syscall_handler.set_handler(0xC7, "getuid32", 0, self._get_uid)
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
        self._clock_start = time.time()
        self._clock_offset = randint(50000, 100000)
        self._sig_maps = {}
        self.__pcb = pcb.get_pcb()
        self._process_name = config.global_config_get("pkg_name") #"ChromiumNet10"
        
    #

    def __do_fork(self, mu):
        logger.info("fork called")
        r = os.fork()
        if (r == 0):
            pass
            #实测这样改没效果
            #logging.basicConfig(level=logging.DEBUG, format='%(process)d - %(asctime)s - %(levelname)s - %(message)s', stream=sys.stdout)
        #
        else:
            logger.info("-----here is parent process child pid=%d"%r)
        #
        return r
    #

    def __fork(self, mu):
        return self.__do_fork(mu)
    #

    def __execve(self, mu, filename_ptr, argv_ptr, envp_ptr):
        filename =memory_helpers.read_utf8(mu, filename_ptr)
        ptr = argv_ptr
        params = []
        logger.info("execve run")
        while True:
            off = memory_helpers.read_ptr(mu, ptr)
            param = memory_helpers.read_utf8(mu, off)
            if (len(param) == 0):
                break
            params.append(param)
            ptr += 4
        #
        logging.warning("execve %s %r"%(filename, params))
        cmd = " ".join(params)

        pkg_name = config.global_config_get("pkg_name")
        pm = "pm path %s"%(pkg_name,)
        if(cmd.find(pm) > -1):
            output = "package:/data/app/%s-1.apk"%pkg_name
            logger.info("write to stdout [%s]"%output)
            os.write(1, output.encode("utf-8"))
            sys.exit(0)
        #
        else:
            raise NotImplementedError()
        #
    #

    def _getpid(self, mu):
        pobj = pcb.get_pcb()
        return pobj.get_pid()
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
        ps = os.pipe2(flags)
        logger.info("pipe return %r"%(ps,))
        self.__pcb.add_fd("[pipe_r]", "[pipe_r]", ps[0])
        self.__pcb.add_fd("[pipe_w]", "[pipe_w]", ps[1])
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
        sa_handler = memory_helpers.read_ptr(mu, act_off)
        act_off+=4
        sa_mask = memory_helpers.read_ptr(mu, act_off)
        act_off+=4
        sa_flag = memory_helpers.read_ptr(mu, act_off)
        act_off+=4
        sa_restorer = memory_helpers.read_ptr(mu, act_off)

        logging.warning("sa_handler [0x%08X] sa_mask [0x%08X] sa_flag [0x%08X] sa_restorer [0x%08X]"%(sa_handler, sa_mask, sa_flag, sa_restorer))
        self._sig_maps[sig] = (sa_handler, sa_mask, sa_flag, sa_restorer)
        return 0
    #

    def _gettid(self, mu):
        #单线程直接用pid代替
        return self._getpid(mu)
    #

    def _setsockopt(self, mu, fd, level, optname, optval, optlen):
        logging.warn("_setsockopt not implement skip")
        return 0
    #

    def _getcpu(self, mu, _cpu, node, cache):
        if _cpu != 0:
            mu.mem_write(_cpu, int(1).to_bytes(4, byteorder='little'))
        return 0

    def _handle_gettimeofday(self, uc, tv, tz):
        """
        If either tv or tz is NULL, the corresponding structure is not set or returned.
        """

        if tv != 0:
            if OVERRIDE_TIMEOFDAY:
                uc.mem_write(tv + 0, int(OVERRIDE_TIMEOFDAY_SEC).to_bytes(4, byteorder='little'))
                uc.mem_write(tv + 4, int(OVERRIDE_TIMEOFDAY_USEC).to_bytes(4, byteorder='little'))
            else:
                timestamp = time.time()
                (usec, sec) = math.modf(timestamp)
                usec = abs(int(usec * 100000))

                uc.mem_write(tv + 0, int(sec).to_bytes(4, byteorder='little'))
                uc.mem_write(tv + 4, int(usec).to_bytes(4, byteorder='little'))

        if tz != 0:
            uc.mem_write(tz + 0, int(-120).to_bytes(4, byteorder='little'))  # minuteswest -(+GMT_HOURS) * 60
            uc.mem_write(tz + 4, int().to_bytes(4, byteorder='little'))  # dsttime

        return 0
    #

    def __wait4(self, mu, pid, wstatus, options, ru):
        assert ru==0
        #return pid
        logger.warning("syscall wait4 pid %d"%pid)
        t = os.wait4(pid, options)
        logger.info("wait4 return %r"%(t,))
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
        logger.warning("syscall sysinfo buf 0x%08X return fixed value"%(info_ptr))
        return 0
    #

    def __clone(self, mu, fn, child_stack, flags, arg1, arg2):
        #FIXME implement...
        #0x01200011 is a code addr?
        #clone(0x01200011, 0x00000000, 0x00000000, 0x00000000, 0x00000008) ???
        #0x01200011 is an invalid addr, a invalid syscall!!!
        logging.warning("syscall clone skip.")
        return -1
        #raise NotImplementedError()
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

        if option == PR_SET_VMA:
            # arg5 contains ptr to a name.
            return 0
        elif option == PR_SET_DUMPABLE:
            return 0
        elif option == PR_GET_NAME:
            memory_helpers.write_utf8(mu, arg2, self._process_name)
            return 0
        elif option == PR_GET_DUMPABLE:
            mu.mem_write(arg2, int(0).to_bytes(4, byteorder='little'))
            return 0
        elif option == PR_SET_NAME:
            self._process_name = memory_helpers.read_utf8(mu, arg2)
            return 0
        else:
            raise NotImplementedError("Unsupported prctl option %d (0x%x)" % (option, option))
        #
    #

    def _handle_sigprocmask(self, mu, how, set, oset):
        return 0
    #

    def __vfork(self, mu):
        return self.__do_fork(mu)
    #

    def _get_uid(self, mu):
        uid = config.global_config_get("uid")
        return uid
    #

    def _handle_futex(self, mu, uaddr, op, val, timeout, uaddr2, val3):
        v = mu.mem_read(uaddr, 4)
        v = int.from_bytes(v, byteorder='little', signed=False)
        logger.info("futext call op=0x%08X *uaddr=0x%08X val=0x%08X"%(op, v, val))
        """
        See: https://linux.die.net/man/2/futex
        """
        cmd = op & FUTEX_CMD_MASK
        if cmd == FUTEX_WAIT or cmd == FUTEX_WAIT_BITSET:
            if v == val:
                raise RuntimeError("ERROR!!! FUTEX_WAIT or FUTEX_WAIT_BITSET dead lock !!! *uaddr == val, impossible for single thread program!!!")
            return 0
        elif cmd == FUTEX_WAKE:
            return 0
        elif cmd == FUTEX_FD:
            raise NotImplementedError()
        elif cmd == FUTEX_REQUEUE:
            raise NotImplementedError()
        elif cmd == FUTEX_CMP_REQUEUE:
            raise NotImplementedError()
        elif cmd == FUTEX_WAKE_BITSET:
            return 0
        else:
            raise NotImplementedError()
        return 0
    #

    def _handle_tgkill(self, mu, tgid, tid, sig):
        if (tgid ==  self._getpid(mu) and sig == 6):
            raise RuntimeError("tgkill abort self,...")
            return 0
        #
        return 0
        if (tgid == self._getpid(mu) and tid == self._gettid(mu)):
            if (sig in self._sig_maps):
                sigact = self._sig_maps[sig]
                addr = sigact[0]

                ctx = memory_helpers.reg_context_save(mu)
                logging.info("_handle_tgkill calling proc 0x%08X sig:0x%X"%(addr, sig))
                mu.reg_write(UC_ARM_REG_R0, sig)
                stop_pos = randint(config.HOOK_MEMORY_BASE, config.HOOK_MEMORY_BASE + config.HOOK_MEMORY_SIZE) | 1
                mu.reg_write(UC_ARM_REG_LR, stop_pos)
                mu.emu_start(addr, stop_pos-1)
                logging.info("_handle_tgkill calling sigal call return")
                memory_helpers.reg_context_restore(mu, ctx)
                print (123)
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

            mu.mem_write(tp_ptr + 0, int(clock_real).to_bytes(4, byteorder='little'))
            mu.mem_write(tp_ptr + 4, int(0).to_bytes(4, byteorder='little'))
            return 0
        elif clk_id == CLOCK_MONOTONIC or clk_id == CLOCK_MONOTONIC_COARSE:
            if OVERRIDE_CLOCK:
                mu.mem_write(tp_ptr + 0, int(OVERRIDE_CLOCK_TIME).to_bytes(4, byteorder='little'))
                mu.mem_write(tp_ptr + 4, int(0).to_bytes(4, byteorder='little'))
            else:
                clock_add = time.time() - self._clock_start  # Seconds passed since clock_start was set.

                mu.mem_write(tp_ptr + 0, int(self._clock_start + clock_add).to_bytes(4, byteorder='little'))
                mu.mem_write(tp_ptr + 4, int(0).to_bytes(4, byteorder='little'))
            return 0
        else:
            raise NotImplementedError("Unsupported clk_id: %d (%x)" % (clk_id, clk_id))

    def _socket(self, mu, family, type_in, protocol):
        s = socket.socket(family, type_in, protocol)
        socket_id = s.fileno()
        self.__pcb.add_fd("[socket]", "[socket]", socket_id)
        return socket_id
    #

    def _bind(self, mu, fd, addr, addr_len):

        # The struct is confusing..
        addr = mu.mem_read(addr + 3, addr_len - 3).decode(encoding="utf-8")

        logger.info('Binding socket to ://%s' % addr)
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
            rbase = memory_helpers.read_ptr(mu, off_r)
            iov_len = memory_helpers.read_ptr(mu, off_r+4)
            tmp = memory_helpers.read_byte_array(mu, rbase, iov_len)
            b+=tmp
            off_r+=8
        #
        off_l = local_iov
        has_read = 0
        for j in range(0, liovcnt):
            lbase = memory_helpers.read_ptr(mu, off_l)
            liov_len = memory_helpers.read_ptr(mu, off_l+4)
            tmp = b[has_read:liov_len]
            has_read += len(tmp)
            off_l += 8
        #
        print(b)
        return has_read
    #