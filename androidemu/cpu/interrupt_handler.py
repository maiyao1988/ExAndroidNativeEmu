import logging
import traceback

from unicorn import *
from unicorn.arm_const import *
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
                logger.error("Unhandled interrupt %d at %x, stopping emulation" % (intno, self._mu.reg_read(UC_ARM_REG_PC)))
                traceback.print_stack()
                self._mu.emu_stop()
                sys.exit(-1)
        except Exception as e:
            logger.exception("exception in _hook_interrupt intno:[%d]"%intno)
            sys.exit(-1)
        #
    #

    def set_handler(self, intno, handler):
        self._handlers[intno] = handler
