import calendar
import logging
import math
import os
import time
import sys
import ctypes
from random import randint

from unicorn import Uc
from unicorn.arm_const import *

from androidemu.const.android import *
from androidemu.const.linux import *
from androidemu.cpu.syscall_handlers import SyscallHandlers
from androidemu.data import socket_info
from androidemu.data.socket_info import SocketInfo
from androidemu.utils import memory_helpers

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
        self._syscall_handler.set_handler(0x2, "fork", 0, self._fork)
        self._syscall_handler.set_handler(0x14, "getpid", 0, self._getpid)
        self._syscall_handler.set_handler(0x1A, "ptrace", 4, self.__ptrace)
        self._syscall_handler.set_handler(0x25, "kill", 2, self.__kill)
        self._syscall_handler.set_handler(0x2A, "pipe", 1, self._pipe)
        self._syscall_handler.set_handler(0x43, "sigaction", 3, self._handle_sigaction)
        self._syscall_handler.set_handler(0x4E, "gettimeofday", 2, self._handle_gettimeofday)
        self._syscall_handler.set_handler(0x72, "wait4", 4, self.__wait4)
        self._syscall_handler.set_handler(0x74, "sysinfo", 1, self.__sysinfo)
        self._syscall_handler.set_handler(0xAC, "prctl", 5, self._handle_prctl)
        self._syscall_handler.set_handler(0xAF, "sigprocmask", 3, self._handle_sigprocmask)
        self._syscall_handler.set_handler(0xC7, "getuid32", 0, self._get_uid)
        self._syscall_handler.set_handler(0xE0, "gettid", 0, self._gettid)
        self._syscall_handler.set_handler(0xF0, "futex", 6, self._handle_futex)
        self._syscall_handler.set_handler(0x10c, "tgkill", 3, self._handle_tgkill)
        self._syscall_handler.set_handler(0x107, "clock_gettime", 2, self._handle_clock_gettime)
        self._syscall_handler.set_handler(0x119, "socket", 3, self._socket)
        self._syscall_handler.set_handler(0x11a, "bind", 3, self._bind)
        self._syscall_handler.set_handler(0x11b, "connect", 3, self._connect)
        self._syscall_handler.set_handler(0x14e, "faccessat", 4, self._faccessat)
        self._syscall_handler.set_handler(0x159, "getcpu", 3, self._getcpu)
        self._syscall_handler.set_handler(0x14e, "faccessat", 4, self._faccessat)
        # self._syscall_handler.set_handler(0x180,"null1",0, self._null)
        self._syscall_handler.set_handler(0x180, "getrandom", 3, self._getrandom)
        self._clock_start = time.time()
        self._clock_offset = randint(1000, 2000)
        self._socket_id = 0x100000
        self._sockets = dict()
        self._sig_maps = {}
        
    #
    def _fork(self, mu):
        logging.warning("skip syscall fork")
        #fork return 0 for child process, return pid for parent process
        #return 0
        return 0x2122
    #

    def _getpid(self, mu):
        return 0x1122
    #

    def __ptrace(self, mu, request, pid, addr, data):
        logging.warning("skip syscall ptrace request [%d] pid [0x%x] addr [0x%08X] data [0x%08X]"%(request, pid, addr, data))
        return 0
    #

    def __kill(self, mu, pid, sig):
        logging.warning("kill is call pid=0x%x sig=%d"%(pid, sig))
        if (pid == self._getpid(mu)):
            logging.error("process 0x%x is killing self!!! maybe encounter anti-debug!!!"%pid)
            #sys.exit(-10)
        #
    #

    def _pipe(self, mu, files):
        logging.warning("skip syscall pipe files [0x%08X]"%files)
        return 0
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
        return 0x2211

    def _faccessat(self, mu, filename, pathname, mode, flag):
        file = memory_helpers.read_utf8(mu, pathname)
        return 0

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

    def __wait4(self, mu, pid, start_addr, options, ru):
        logger.warning("skip syscall wait4 pid [0x%x]"%pid)
        return 0
    #

    def __sysinfo(self, mu, info):
        logger.warning("skip syscall sysinfo buf 0x%08X just return error"%(info))
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

        if option == PR_SET_VMA:
            # arg5 contains ptr to a name.
            return 0
        elif option == PR_SET_DUMPABLE:
            return 0
        else:
            raise NotImplementedError("Unsupported prctl option %d (0x%x)" % (option, option))
        #
    #

    def _handle_sigprocmask(self, mu, how, set, oset):
        return 0
    #

    def _get_uid(self, mu):
        #return a android valid app uid, which is >10000
        return 10023
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
            logger.warn("tgkill abort self, skip!!!")
            return 0
        #
        if (tgid == self._getpid(mu) and tid == self._gettid(mu)):
            if (sig in self._sig_maps):
                sigact = self._sig_maps[sig]
                addr = sigact[0]

                ctx = memory_helpers.reg_context_save(mu)
                mu.reg_write(UC_ARM_REG_R0, sig)
                logging.info("_handle_tgkill calling proc 0x%08X sig:0x%X"%(addr, sig))
                mu.emu_start(addr, 0xFFFFFFFF)
                logging.info("_handle_tgkill calling sigal call return")
                memory_helpers.reg_context_restore(mu, ctx)
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
        socket_id = self._socket_id + 1
        socket = SocketInfo()
        socket.domain = family
        socket.type = type_in
        socket.protocol = protocol

        self._sockets[socket_id] = socket
        self._socket_id = self._socket_id + 1

        return socket_id

    def _bind(self, mu, fd, addr, addr_len):
        socket = self._sockets.get(fd, None)

        if socket is None:
            raise Exception('Expected a socket')

        if socket.domain != socket_info.AF_UNIX and socket.type != socket_info.SOCK_STREAM:
            raise Exception('Unexpected socket domain / type.')

        # The struct is confusing..
        socket.addr = mu.mem_read(addr + 3, addr_len - 3).decode(encoding="utf-8")

        logger.info('Binding socket to ://%s' % socket.addr)

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

    def _getrandom(self, mu, buf, count, flags):
        mu.mem_write(buf, b"\x01" * count)
        return count
