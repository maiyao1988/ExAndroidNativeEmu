import logging

from unicorn import *
from unicorn.arm_const import *

from .interrupt_handler import InterruptHandler
from .syscall_handler import SyscallHandler
from ..utils import memory_helpers
import unicorn
import traceback
import sys

logger = logging.getLogger(__name__)


class SyscallHandlers:

    """
    :type interrupt_handler InterruptHandler
    """
    def __init__(self, interrupt_handler):
        self._handlers = dict()
        interrupt_handler.set_handler(2, self._handle_syscall)
    #

    def set_handler(self, idx, name, arg_count, callback):
        self._handlers[idx] = SyscallHandler(idx, name, arg_count, callback)

    def _handle_syscall(self, mu):
        idx = mu.reg_read(UC_ARM_REG_R7)
        lr = mu.reg_read(UC_ARM_REG_LR)
        logger.info("syscall %d lr=0x%08X", idx, lr)
        args = [mu.reg_read(reg_idx) for reg_idx in range(UC_ARM_REG_R0, UC_ARM_REG_R6 + 1)]

        if idx in self._handlers:
            handler = self._handlers[idx]
            args = args[:handler.arg_count]
            args_formatted = ", ".join(["0x%08X" % arg for arg in args])
            logger.debug("Executing syscall %s(%s) at 0x%08X" % (handler.name, args_formatted,
                                                               mu.reg_read(UC_ARM_REG_PC)))

            try:
                result = handler.callback(mu, *args)
            except:
                logger.exception("An error occured during in %x syscall hander, stopping emulation" % idx)
                mu.emu_stop()
                raise

            if result is not None:
                mu.reg_write(UC_ARM_REG_R0, result)
        else:

            args_formatted = ", ".join(["0x%08X" % arg for arg in args])
            error = "Unhandled syscall 0x%x (%u) at 0x%x, args(%s) stopping emulation" % (idx, idx,
                                                                                      mu.reg_read(UC_ARM_REG_PC), args_formatted)
            
            logger.exception(error)
            mu.emu_stop()
            raise RuntimeError(error)
            
