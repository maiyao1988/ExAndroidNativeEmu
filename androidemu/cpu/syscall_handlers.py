import logging

from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *

from .interrupt_handler import InterruptHandler
from .syscall_handler import SyscallHandler
from ..utils import memory_helpers
from ..const import emu_const
import unicorn
import traceback
import sys


class SyscallHandlers:

    """
    :type interrupt_handler InterruptHandler
    """
    def __init__(self, mu, schduler, arch):
        self._handlers = dict()
        self.__sch = schduler
        self.__interrupt_handler = InterruptHandler(mu)
        if (arch == emu_const.ARCH_ARM32):
            self.__interrupt_handler.set_handler(2, self._handle_syscall)
        else:
            #arm64
            self.__interrupt_handler.set_handler(2, self._handle_syscall64)
        #
    #

    def set_handler(self, idx, name, arg_count, callback):
        self._handlers[idx] = SyscallHandler(idx, name, arg_count, callback)
    #

    def _handle_syscall(self, mu):
        idx = mu.reg_read(UC_ARM_REG_R7)
        lr = mu.reg_read(UC_ARM_REG_LR)
        tid = self.__sch.get_current_tid()
        logging.debug("%d syscall %d lr=0x%08X", tid, idx, lr)
        args = [mu.reg_read(reg_idx) for reg_idx in range(UC_ARM_REG_R0, UC_ARM_REG_R6 + 1)]
        if idx in self._handlers:
            handler = self._handlers[idx]
            args = args[:handler.arg_count]
            args_formatted = ", ".join(["0x%08X" % arg for arg in args])
            logging.debug("%d Executing syscall %s(%s) at 0x%08X" % (tid, handler.name, args_formatted, mu.reg_read(UC_ARM_REG_PC)))
            try:
                result = handler.callback(mu, *args)
            except:
                logging.exception("%d An error occured during in %x syscall hander, stopping emulation" % (tid, idx))
                mu.emu_stop()
                raise

            if result is not None:
                mu.reg_write(UC_ARM_REG_R0, result)
        else:
            args_formatted = ", ".join(["0x%08X" % arg for arg in args])
            error = "%d Unhandled syscall 0x%x (%u) at 0x%x, args(%s) stopping emulation" % (tid, idx, idx,
                                                                                      mu.reg_read(UC_ARM_REG_PC), args_formatted)
            
            logging.exception(error)
            mu.emu_stop()
            raise RuntimeError(error)
        #
    #
    def _handle_syscall64(self, mu):
        idx = mu.reg_read(UC_ARM64_REG_X8)
        lr = mu.reg_read(UC_ARM64_REG_LR)
        tid = self.__sch.get_current_tid()

        logging.debug("%d syscall %d lr=0x%016X", tid, idx, lr)
        args = [mu.reg_read(reg_idx) for reg_idx in range(UC_ARM64_REG_X0, UC_ARM64_REG_X6 + 1)]

        if idx in self._handlers:
            handler = self._handlers[idx]
            args = args[:handler.arg_count]
            args_formatted = ", ".join(["0x%016X" % arg for arg in args])
            logging.debug("%d Executing syscall %s(%s) at 0x%016X" % (tid, handler.name, args_formatted, mu.reg_read(UC_ARM64_REG_PC)))
            try:
                result = handler.callback(mu, *args)
            except:
                logging.exception("%d An error occured during in %x syscall hander, stopping emulation" % (tid, idx))
                mu.emu_stop()
                raise

            if result is not None:
                mu.reg_write(UC_ARM64_REG_X0, result)
        else:
            args_formatted = ", ".join(["0x%016X" % arg for arg in args])
            error = "%d Unhandled syscall 0x%x (%u) at 0x%x, args(%s) stopping emulation" % (tid, idx, idx,
                                                                                      mu.reg_read(UC_ARM64_REG_PC), args_formatted)
            
            logging.exception(error)
            mu.emu_stop()
            raise RuntimeError(error)
        #
    #
#
