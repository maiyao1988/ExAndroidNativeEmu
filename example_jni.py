import logging
import posixpath
import sys
import os

from unicorn import UcError, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn.arm_const import *

from androidemu.emulator import Emulator
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_method_def import java_method_def
import androidemu.config

import capstone


# Create java class.
from samples import debug_utils

g_md_thumb = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
g_md_thumb.detail = True

g_md_arm = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
g_md_arm.detail = True

def hex_to_int32(hex):
    i = int(hex, 16)
    if (i > 0x7FFFFFFF):
        i = i - 1<<32
    #
    return i
#

# Add debugging.
def hook_code(mu, address, size, user_data):
    try:
        instruction = mu.mem_read(address, size)
        emu = user_data
        ms = emu.modules
        #判断是否arm，用不同的decoder
        b = mu.reg_read(UC_ARM_REG_CPSR)
        if (b & (1<<5)):
            md = g_md_thumb
        else:
            md = g_md_arm
        #
        codes = md.disasm(instruction, 0)
        m = 0
        for i in codes:
            addr = i.address + address
            name = "unknown"
            module = None
            base = 0
            funName = None
            for m in ms:
                if (addr >= m.base and addr <= m.base+m.size):
                    module = m
                    break
                #
            #
            if (module != None):
                name = os.path.basename(module.filename)
                base = module.base
                funName = module.is_symbol_addr(addr)
            #
            
            if (base == 0 and (addr < androidemu.config.HEAP_BASE or addr>androidemu.config.HEAP_BASE+androidemu.config.HEAP_SIZE) and \
            (addr<androidemu.config.HOOK_MEMORY_BASE or addr>androidemu.config.HOOK_MEMORY_BASE+androidemu.config.HOOK_MEMORY_SIZE)):
                logger.error("code %s\t%s in addr 0x%08X out of range"%(i.mnemonic, i.op_str, addr))
                sys.exit(-1)
            #
            
            instruction_str = ''.join('{:02X} '.format(x) for x in i.bytes)
            #print("sz:%d", size)
            line = "(%20s)[%-12s]0x%08X:\t%s\t%s"%(name, instruction_str, addr-base, i.mnemonic, i.op_str)
            if (funName != None):
                line = line + " ; %s"%funName
            #
            print(line)
        #
    except Exception as e:
        logger.exception("exception in hook_code")
        sys.exit(-1)
    #
#

class MainActivity(metaclass=JavaClassDef, jvm_name='local/myapp/testnativeapp/MainActivity'):

    def __init__(self):
        pass

    @java_method_def(name='stringFromJNI', signature='()Ljava/lang/String;', native=True)
    def string_from_jni(self, mu):
        pass

    def test(self):
        pass


# Configure logging
logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)7s %(name)34s | %(message)s"
)

logger = logging.getLogger(__name__)

# Initialize emulator
emulator = Emulator(
    vfp_inst_set=True,
    vfs_root=posixpath.join(posixpath.dirname(__file__), "vfs")
)

# Register Java class.
emulator.java_classloader.add_class(MainActivity)

emulator.mu.hook_add(UC_HOOK_CODE, hook_code, emulator)
# Load all libraries.
emulator.load_library("samples/example_binaries/libdl.so")
emulator.load_library("samples/example_binaries/libc.so")
emulator.load_library("samples/example_binaries/libstdc++.so")
emulator.load_library("samples/example_binaries/libm.so")
lib_module = emulator.load_library("samples/example_binaries/libnative-lib_jni.so")

for m in emulator.modules:
    for addr in m.symbol_lookup:
        v = m.symbol_lookup[addr]
        print ("%08X(%08X):%s"%(addr, addr - m.base, v[0]))
    #
#
sys.exit(-1)
# Show loaded modules.
logger.info("Loaded modules:")

for module in emulator.modules:
    logger.info("=> 0x%08x - %s" % (module.base, module.filename))

# Debug
# emulator.mu.hook_add(UC_HOOK_CODE, debug_utils.hook_code)
# emulator.mu.hook_add(UC_HOOK_MEM_UNMAPPED, debug_utils.hook_unmapped)
# emulator.mu.hook_add(UC_HOOK_MEM_WRITE, debug_utils.hook_mem_write)
# emulator.mu.hook_add(UC_HOOK_MEM_READ, debug_utils.hook_mem_read)

try:
    # Run JNI_OnLoad.
    #   JNI_OnLoad will call 'RegisterNatives'.
    emulator.call_symbol(lib_module, 'JNI_OnLoad', emulator.java_vm.address_ptr, 0x00)
    emulator.mu.hook_add(UC_HOOK_MEM_UNMAPPED, debug_utils.hook_unmapped)

    # Do native stuff.
    main_activity = MainActivity()
    logger.info("Response from JNI call: %s" % main_activity.string_from_jni(emulator))

    # Dump natives found.
    logger.info("Exited EMU.")
    logger.info("Native methods registered to MainActivity:")

    for method in MainActivity.jvm_methods.values():
        if method.native:
            logger.info("- [0x%08x] %s - %s" % (method.native_addr, method.name, method.signature))
except UcError as e:
    print("Exit at %x" % emulator.mu.reg_read(UC_ARM_REG_PC))
    raise
