import logging
import posixpath
import sys
import os

from unicorn import *
from unicorn.arm_const import *

from androidemu.emulator import Emulator
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_method_def import java_method_def
from androidemu.java.java_field_def import JavaFieldDef
from androidemu.java.classes.string import String
import androidemu.utils.debug_utils 
from androidemu.utils.chain_log import ChainLogger

import capstone
import traceback

g_cfd = ChainLogger(sys.stdout, "./ins-bb.txt")

# Add debugging.
def hook_code(mu, address, size, user_data):
    try:
        emu = user_data
        if (not emu.memory.check_addr(address, UC_PROT_EXEC)):
            logger.error("addr 0x%08X out of range"%(address,))
            sys.exit(-1)
        #
        #androidemu.utils.debug_utils.dump_registers(mu, sys.stdout)
        androidemu.utils.debug_utils.dump_code(emu, address, size, g_cfd)
    except Exception as e:
        logger.exception("exception in hook_code")
        sys.exit(-1)
    #
#

class Helper(metaclass=JavaClassDef, jvm_name='com/SecShell/SecShell/Helper',
jvm_fields=[
                     JavaFieldDef('PKGNAME', 'Ljava/lang/String;', True, String("com.myxh.coolshopping"))
                 ]):

    def __init__(self):
        pass

    @java_method_def(name='azbycx', signature='(Ljava/lang/String;)Ljava/lang/String;', native=True)
    def azbycx(self, mu):
        pass
    #
#

class DexInstall(metaclass=JavaClassDef, jvm_name='com/SecShell/SecShell/DexInstall'):
    def __init__(self):
        pass
    #
    @staticmethod
    @java_method_def(name='install', args_list=["jobject", "jstring", "jstring"], signature='(Ljava/lang/ClassLoader;Ljava/lang/String;Ljava/lang/String;)V', native=False)
    def install(mu, obj, s1, s2):
        print("DexInstall install arg %r %s %s"%(obj, s1, s2))
    #
#

class DexInstallV26(metaclass=JavaClassDef, jvm_name='com/SecShell/SecShell/DexInstall$V26'):
    def __init__(self):
        pass
    #

    @staticmethod
    @java_method_def(name='install', args_list=["jobject", "jstring"], signature='(Ljava/lang/ClassLoader;Ljava/lang/String;)V', native=False)
    def install(mu, obj, s):
        print("DexInstallV26 install arg %r %s %s"%(obj, s))
    #
#

logger = logging.getLogger(__name__)

# Initialize emulator
emulator = Emulator(
    vfs_root=posixpath.join(posixpath.dirname(__file__), "vfs")
)

# Register Java class.
emulator.java_classloader.add_class(Helper)
emulator.java_classloader.add_class(DexInstall)
emulator.java_classloader.add_class(DexInstallV26)
#emulator.mu.hook_add(UC_HOOK_CODE, hook_code, emulator)

# Load all libraries.
lib_module2 = emulator.load_library("vfs/system/lib/libdvm.so")
lib_module = emulator.load_library("tests/bin/libSecShell.so")
#lib_module = emulator.load_library("../deobf/sec.so")
#androidemu.utils.debug_utils.dump_symbols(emulator, sys.stdout)

# Show loaded modules.
logger.info("Loaded modules:")

for module in emulator.modules:
    logger.info("=> 0x%08x - %s" % (module.base, module.filename))

try:
    # Run JNI_OnLoad.
    #   JNI_OnLoad will call 'RegisterNatives'.
    print ("call JNI_OnLoad")
    emulator.call_symbol(lib_module, 'JNI_OnLoad', emulator.java_vm.address_ptr, 0x00)

except UcError as e:
    print("Exit at %x" % emulator.mu.reg_read(UC_ARM_REG_PC))
    raise

