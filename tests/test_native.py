import logging
import posixpath
import sys
import unittest

from androidemu.emulator import Emulator
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_method_def import java_method_def
from androidemu.java.classes.string import String
from androidemu.java.classes.types import *
from androidemu.java.classes.context import *
from androidemu.java.classes.array import *
from androidemu.java.classes.map import *
from androidemu.java.classes.activity_thread import *
from androidemu.utils.chain_log import ChainLogger
from androidemu.java.constant_values import *
from androidemu.vfs.virtual_file import VirtualFile
from androidemu.const import emu_const
from androidemu.utils import misc_utils, debug_utils, memory_helpers
from unicorn import UcError

from androidemu.utils import debug_utils
logger = logging.getLogger(__name__)

class TestClass(metaclass=JavaClassDef, jvm_name='com/dingxiang/demo/TestClass'):

    def __init__(self):
        pass
    #

    @java_method_def(name='testJni1', signature='(Landroid/content/Context;)Ljava/lang/String;', native=True)
    def testJni1(self, mu, ctx):
        pass
    #

    @java_method_def(name='testJni2', signature='(J)J', native=True)
    def testJni2(self, mu, n):
        pass
    #

#



class TestNative(unittest.TestCase):

    def test_something(self):
        # Initialize emulator
        emulator = Emulator(
            vfp_inst_set=True,
            vfs_root="vfs"
        )

        module = emulator.load_library(posixpath.join(posixpath.dirname(__file__), "bin", "test_native.so"))

        self.assertTrue(module.base != 0)

        #emulator.mu.hook_add(UC_HOOK_CODE, hook_code, emulator)
        res = emulator.call_symbol(module, 'Java_com_aeonlucid_nativetesting_MainActivity_testOneArg', emulator.java_vm.jni_env.address_ptr, 0x00, String('Hello'))
        pystr = emulator.java_vm.jni_env.get_local_reference(res).value.get_py_string()
        self.assertEqual(pystr, "Hello")
    #

    def __test_tls_common(self, emulator, libcm):
        env_key_ptr = emulator.call_symbol(libcm, "malloc", 100)
        memory_helpers.write_utf8(emulator.mu, env_key_ptr, "ANDROID_ROOT")
        env_ptr = emulator.call_symbol(libcm, "getenv", env_key_ptr)
        self.assertTrue(env_ptr!=0)
        env_str = memory_helpers.read_utf8(emulator.mu, env_ptr)
        emulator.call_symbol(libcm, "free", env_key_ptr)
        self.assertEqual(env_str, "/system")

        key_buf_ptr = emulator.call_symbol(libcm, "malloc", 100)
        emulator.call_symbol(libcm, "pthread_key_create", key_buf_ptr, 0)
        key = memory_helpers.read_ptr_sz(emulator.mu, key_buf_ptr, emulator.get_ptr_size())
        target_int = 3000
        emulator.call_symbol(libcm, "pthread_setspecific", key, target_int)

        r = emulator.call_symbol(libcm, "pthread_getspecific", key)
        emulator.call_symbol(libcm, "free", key_buf_ptr)
        self.assertEqual(r, target_int)
    #

    def test_tls32(self):
        try:
            emulator = Emulator(
                vfs_root="vfs"
            )
            #测试getenv，pthread_getspecific等涉及tls_init的代码是否正常
            libcm = emulator.load_library("vfs/system/lib/libc.so")
            self.__test_tls_common(emulator, libcm)
        except UcError as e:
            print("Exit at 0x%08X" % emulator.mu.reg_read(UC_ARM_REG_PC))
            emulator.memory.dump_maps(sys.stdout)
            raise
        #
    #

    def test_tls64(self):
        try:
            emulator = Emulator(
                vfs_root="vfs",
                arch=emu_const.ARCH_ARM64
            )
            #测试getenv，pthread_getspecific等涉及tls_init的代码是否正常
            libcm = emulator.load_library("vfs/system/lib64/libc.so")
            self.__test_tls_common(emulator, libcm)
        except UcError as e:
            print("Exit at 0x%08X" % emulator.mu.reg_read(UC_ARM64_REG_PC))
            emulator.memory.dump_maps(sys.stdout)
            raise
        #
    #

    def test_64_elf(self):

        # Initialize emulator
        emulator = Emulator(
            vfs_root="vfs",
            arch=emu_const.ARCH_ARM64
        )
        emulator.java_classloader.add_class(TestClass)

        try:
            libcm = emulator.load_library("vfs/system/lib64/libc.so")
            libtest = emulator.load_library("tests/bin64/libnative-lib.so")
            #emulator.memory.dump_maps(sys.stdout)
            emulator.call_symbol(libtest, 'JNI_OnLoad', emulator.java_vm.address_ptr, 0x00)
            t = TestClass()
            r = t.testJni2(emulator, 10000000000)
            self.assertEqual(r, 125)
            app = ActivityThread.currentApplication(emulator)
            s = t.testJni1(emulator, app).get_py_string()
            self.assertEqual(s, "com.ss.android.ugc.aweme")
            #emulator.memory.dump_maps(sys.stdout)

        except UcError as e:
            print("Exit at 0x%08X" % emulator.mu.reg_read(UC_ARM64_REG_PC))
            emulator.memory.dump_maps(sys.stdout)
            raise
        #
    #

    def test_load_bias_new_delete(self):
        emulator = Emulator(
            vfs_root="vfs",
            arch=emu_const.ARCH_ARM64
        )
        try:
            libcpp = emulator.load_library("vfs/system/lib64/libc++.so")
            new_ptr = emulator.call_symbol(libcpp, "_Znwm", 100)
            emulator.mu.mem_write(new_ptr, b'hello world...')
            self.assertTrue(new_ptr!=0)
            emulator.call_symbol(libcpp, "_ZdlPv", new_ptr)
        #
        except UcError as e:
            print("Exit at 0x%08X" % emulator.mu.reg_read(UC_ARM64_REG_PC))
            emulator.memory.dump_maps(sys.stdout)
            raise
        #
    #
#
