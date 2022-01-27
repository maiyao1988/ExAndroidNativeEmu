import logging
import traceback
import inspect

from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *

import sys

logger = logging.getLogger(__name__)


class InterruptHandler:

    """
    :type mu Uc
    """
    def __init__(self, mu):
        self._mu = mu
        self._mu.hook_add(UC_HOOK_INTR, self._hook_interrupt)
        self._handlers = dict()

    def _hook_interrupt(self, uc, intno, data):
        try:
            if intno in self._handlers:
                self._handlers[intno](uc)
            else:
                pc = 0
                arch = self._mu.query(UC_QUERY_ARCH)
                if arch == UC_ARCH_ARM:
                    pc = self._mu.reg_read(UC_ARM_REG_PC)
                elif arch == UC_ARCH_ARM64:
                    pc = self._mu.reg_read(UC_ARM64_REG_PC)
                #
                logger.error("Unhandled interrupt %d at %x, stopping emulation" % (intno, pc))
                traceback.print_stack()
                frame = inspect.currentframe()
                stack_trace = traceback.format_stack(frame)
                logging.error("catch error on _hook_interrupt")
                logging.error(stack_trace[:-1])
                self._mu.emu_stop()
                sys.exit(-1)
        except Exception as e:
            logger.exception("exception in _hook_interrupt intno:[%d]"%intno)
            sys.exit(-1)
        #
    #

    def set_handler(self, intno, handler):
        self._handlers[intno] = handler
