import logging
import posixpath
import sys
import unittest

from unicorn import *
from androidemu.utils import debug_utils

from androidemu.emulator import Emulator
from androidemu.java.classes.string import String

logger = logging.getLogger(__name__)

def hook_code(mu, address, size, user_data):
    try:
        emu = user_data
        if (not emu.memory.check_addr(address, UC_PROT_EXEC)):
            logger.error("addr 0x%08X out of range"%(address,))
            sys.exit(-1)
        #
        #androidemu.utils.debug_utils.dump_registers(mu, sys.stdout)
        debug_utils.dump_code(emu, address, size, sys.stdout)
    except Exception as e:
        logger.exception("exception in hook_code")
        sys.exit(-1)
    #
#

class TestNative(unittest.TestCase):

    def test_something(self):
        # Initialize emulator
        emulator = Emulator(
            vfp_inst_set=True,
            vfs_root="vfs"
        )

        module = emulator.load_library(posixpath.join(posixpath.dirname(__file__), "bin", "test_native.so"), do_init=False)

        self.assertTrue(module.base != 0)

        #emulator.mu.hook_add(UC_HOOK_CODE, hook_code, emulator)
        res = emulator.call_symbol(module, 'Java_com_aeonlucid_nativetesting_MainActivity_testOneArg', emulator.java_vm.jni_env.address_ptr, 0x00, String('Hello'))
        pystr = res.get_py_string()
        self.assertEqual(pystr, "Hello")
    #
#
