import logging
import posixpath
import sys
import unittest
from androidemu.const import emu_const
from androidemu.emulator import Emulator
from androidemu.native_hook_utils import FuncHooker

class TestThread(unittest.TestCase):
    def __init__(self, methodName):
        unittest.TestCase.__init__(self, methodName)
        self.__is32_before_call = False
        self.__is32_after_call = False

        self.__is64_before_call = False
        self.__is64_after_call = False
    #

    def __pthread_create32_before_hook(self, emu, *arg):
        start_routine = arg[2]
        logging.warning("pthread_create call thread:[0x%08X] attr:[0x%08X] start_routine:[0x%08X] arg:[0x%08X]"%(arg[0], arg[1], start_routine, arg[3]))
        self.__is32_before_call = True
        self.assertTrue(start_routine != 0)
        return False
    #

    def __pthread_create32_after_hook(self, emu, r0, r1):
        logging.warning("pthread_create return 0x%08X"%(r0,))
        self.__is32_after_call = True
        self.assertEqual(r0, 0)
        return False
    #


    def test_thread32(self):
        emulator = Emulator(
            vfs_root="vfs",
            muti_task=True
        )
        libcm = emulator.load_library("vfs/system/lib/libc.so")
        sym = libcm.find_symbol("pthread_create")
        h = FuncHooker(emulator)
        h.fun_hook(sym, 4, self.__pthread_create32_before_hook, self.__pthread_create32_after_hook)
        libdemo = emulator.load_library("tests/bin/libdemo.so")
        r = emulator.call_symbol(libdemo, "test_thread", 3)
        self.assertEqual(r, 3)
        self.assertTrue(self.__is32_before_call)
        self.assertTrue(self.__is32_after_call)
    #


    def __pthread_create64_before_hook(self, emu, *arg):
        start_routine = arg[2]
        logging.warning("pthread_create call thread:[0x%08X] attr:[0x%08X] start_routine:[0x%08X] arg:[0x%08X]"%(arg[0], arg[1], start_routine, arg[3]))
        self.assertTrue(start_routine != 0)

        self.__is64_before_call = True
        return False
    #

    def __pthread_create64_after_hook(self, emu, r0, r1):
        logging.warning("pthread_create 64 return 0x%08X"%(r0,))
        self.__is64_after_call = True
        self.assertEqual(r0, 0)
        return False
    #

    def test_thread64(self):
        emulator = Emulator(
            vfs_root="vfs",
            arch=emu_const.ARCH_ARM64,
            muti_task=True
        )
        libcm = emulator.load_library("vfs/system/lib64/libc.so")
        sym = libcm.find_symbol("pthread_create")
        #print("sym : %s"%hex(sym))
        h = FuncHooker(emulator)
        h.fun_hook(sym, 4, self.__pthread_create64_before_hook, self.__pthread_create64_after_hook)
        #emulator.mu.hook_add(UC_HOOK_CODE, hook_code, emulator)
        libdemo = emulator.load_library("tests/bin64/libdemo.so")
        r = emulator.call_symbol(libdemo, "test_thread", 3)
        self.assertEqual(r, 3)

        self.assertTrue(self.__is64_before_call)
        self.assertTrue(self.__is64_after_call)
    #
#
