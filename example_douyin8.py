import logging
import posixpath
import sys
import os.path
import random

from unicorn import *
from unicorn.arm_const import *

from androidemu.emulator import Emulator
import androidemu.utils.debug_utils
from androidemu.utils import misc_utils
from androidemu.java.helpers.native_method import native_method
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_method_def import java_method_def
from androidemu.utils.chain_log import ChainLogger
from androidemu.java.classes.string import String
from androidemu.java.classes.list import List
from androidemu.java.classes.array import Array
from androidemu.java.constant_values import *
from androidemu.utils.mem_monitor import MemoryMonitor


class XGorgen(metaclass=JavaClassDef, jvm_name='com/ss/sys/ces/a'):
    def __init__(self):
        pass

    @staticmethod
    @java_method_def(name='leviathan', signature='(I[B)[B', native=True)
    def leviathan(mu):
        pass
    #

    @staticmethod
    @java_method_def(name='meta', signature='(ILandroid/content/Context;Ljava/lang/Object;)Ljava/lang/Object;', native=True)
    def meta(mu, optype, ctx, obj):
        pass
    #

    @staticmethod
    @java_method_def(name='Francies', signature='()V', native=False)
    def Francies(mu):
        pass
    #

    @staticmethod
    @java_method_def(name='Bill', signature='()V', native=False)
    def Bill(mu):
        pass
    #

    
    @staticmethod
    @java_method_def(name='Louis', signature='()V', native=False)
    def Louis(mu):
        pass
    #

    @staticmethod
    @java_method_def(name='Zeoy', signature='()V', native=False)
    def Zeoy(mu):
        pass
    #

    @staticmethod
    @java_method_def(name='njss', args_list=["jint", "jobject"], signature='(ILjava/lang/Object;)Ljava/lang/Object;', native=False)
    def njss(mu, i1, o1):
        print("njss arg %d %s" % (i1, o1))
        if i1 == 131:
            return String("eyJvcyI6IkFuZHJvaWQiLCJ2ZXJzaW9uIjoiMS4wLjMiLCJ0b2tlbl9pZCI6IiIsImNvZGUiOjUwNH0=")
        elif i1 == 130:
            return String("00:00:00:00:00:00[<!>]TP-LINK_49lnLeA[<!>]2026350784[<!>]")
        elif i1 == 124:
            return String('[]')
        elif i1 == 125:
            return String("113.4363886,22.382336")
        elif i1 == 129:
            return String("420[<!>]1080*1794[<!>]")
        elif i1 == 126:
            return String("2600")
        elif i1 == 120:
            return String('''{"core":6,"hw":"MT6795","max":"1440000","min":"384000","ft":"fp asimd evtstrm aes pmull sha1 sha2 crc32 wp half thumb fastmult vfp edsp neon vfpv3 tlsi vfpv4 idiva idivt"}''')
        elif i1 == 127:
            return String("357710060743807")
        elif i1 == 128:
            return String("460020862550230")
        elif i1 == 122:
            return String("GMT+08:00")
        elif i1 == 121:
            return String("zh_CN")
        elif i1 == 134:
            return String("-0.1, 0.6, -9.8")
        elif i1 == 133:
            return String('{}')

        return JAVA_NULL
#


class UserInfo(metaclass=JavaClassDef, jvm_name='com/ss/android/common/applog/UserInfo'):
    def __init__(self):
        pass

class java_lang_StackTraceElement(metaclass=JavaClassDef, jvm_name='java/lang/StackTraceElement'):
    def __init__(self, _name):
        self.name = _name

    @java_method_def(native=False, name='getClassName', signature="()Ljava/lang/String;")
    def getClassName(self, *args, **kwargs):
        return self.name


class java_lang_Thread(metaclass=JavaClassDef, jvm_name='java/lang/Thread'):
    def __init__(self):
        pass

    @java_method_def(name="currentThread", signature='()Ljava/lang/Thread;', native=False)
    def currentThread(self, *args, **kwargs):
        return java_lang_Thread()

    @java_method_def(name="getStackTrace", signature='()[Ljava/lang/StackTraceElement;', native=False)
    def getStackTrace(self, *args, **kwargs):
        l = [java_lang_StackTraceElement(String("dalvik.system.VMStack")),
                java_lang_StackTraceElement(String("java.lang.Thread")),
                java_lang_StackTraceElement(String("com.ss.sys.ces.a")),
                java_lang_StackTraceElement(String("com.ss.sys.ces.gg.tt$1")),
                java_lang_StackTraceElement(String("com.bytedance.frameworks.baselib.network.http.e.a")),
                java_lang_StackTraceElement(String("com.bytedance.ttnet.a.a.onCallToAddSecurityFactor")),
                java_lang_StackTraceElement(String("android.support.v7.app.AppCompatViewInflater$DeclaredOnClickListener")),
                java_lang_StackTraceElement(String("java.lang.reflect.Method")),
                java_lang_StackTraceElement(String("com.ttnet.org.chromium.base.Reflect.on")),
                java_lang_StackTraceElement(String("com.ttnet.org.chromium.base.Reflect.call")),
                java_lang_StackTraceElement(String("org.chromium.c.a")),
                java_lang_StackTraceElement(String("org.chromium.e.onCallToAddSecurityFactor")),
                java_lang_StackTraceElement(String("com.ttnet.org.chromium.net.impl.CronetUrlRequestContext")),
                java_lang_StackTraceElement(String("com.ttnet.org.chromium.net.impl.CronetUrlRequest")),
                ]
        return List(l)
    #
#

def hook_mem_read(uc, access, address, size, value, user_data):  
    mnt = user_data
    pc = uc.reg_read(UC_ARM_REG_PC)
    mnt.feed_read(pc, address, size)
#

def hook_mem_write(uc, access, address, size, value, user_data):
    mnt = user_data
    pc = uc.reg_read(UC_ARM_REG_PC)
    mnt.feed_write(pc, address, size)
#

g_cfd = ChainLogger(sys.stdout, "./ins-douyin.txt")

# Add debugging.
def hook_code(mu, address, size, user_data):
    try:
        emu = user_data
        if (not emu.memory.check_addr(address, UC_PROT_EXEC)):
            logger.error("addr 0x%08X out of range" % (address,))
            sys.exit(-1)
        #
        # androidemu.utils.debug_utils.dump_registers(mu, sys.stdout)
        # androidemu.utils.debug_utils.dump_code(emu, address, size, sys.stdout)
        androidemu.utils.debug_utils.dump_code(emu, address, size, sys.stdout)
    except Exception as e:
        logger.exception("exception in hook_code")
        sys.exit(-1)
    #
#

logger = logging.getLogger(__name__)

# Initialize emulator
emulator = Emulator(
    vfs_root=posixpath.join(posixpath.dirname(__file__), "vfs")
)
mnt = MemoryMonitor(emulator)

# Register Java class.
# emulator.java_classloader.add_class(MainActivity)
emulator.java_classloader.add_class(XGorgen)
emulator.java_classloader.add_class(UserInfo)
emulator.java_classloader.add_class(java_lang_Thread)
emulator.java_classloader.add_class(java_lang_StackTraceElement)

# Load all libraries.
libdvm = emulator.load_library("vfs/system/lib/libdvm.so")

libcm = emulator.load_library("vfs/system/lib/libc.so")

#emulator.mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write, mnt)
lib_module = emulator.load_library("tests/bin/libcms8.so")

# Show loaded modules.
logger.info("Loaded modules:")

for module in emulator.modules:
    logger.info("=> 0x%08x - %s" % (module.base, module.filename))

try:

    # Run JNI_OnLoad.
    #   JNI_OnLoad will call 'RegisterNatives'.
    emulator.call_symbol(lib_module, 'JNI_OnLoad', emulator.java_vm.address_ptr, 0x00)


    print("begin meta")
    
    XGorgen.meta(emulator, 101, 0, String("0"))
    XGorgen.meta(emulator, 102, 0, String("1128"))
    XGorgen.meta(emulator, 1020, 0, String(""))

    XGorgen.meta(emulator, 103, 0, String("5179025446"))
    XGorgen.meta(emulator, 104, 0, String("110943176729"))

    XGorgen.meta(emulator, 105, 0, String("850"))
    
    XGorgen.meta(emulator, 106, 0, String("com.ss.android.ugc.aweme"))
    
    XGorgen.meta(emulator, 107, 0, String("/data/user/0/com.ss.android.ugc.aweme/files"))
    XGorgen.meta(emulator, 108, 0, String("/data/app/com.ss.android.ugc.aweme-1.apk"))
    XGorgen.meta(emulator, 109, 0, String("/storage/emulated/0"))
    XGorgen.meta(emulator, 110, 0, String("/data"))
    
    data = 'acde74a94e6b493a3399fac83c7c08b35D58B21D9582AF77647FC9902E36AE70f9c001e9334e6e94916682224fbe4e5f00000000000000000000000000000000'
    data = bytearray(bytes.fromhex(data))
    n = 1562848170
    arr = Array(data)
    
    #emulator.mu.hook_add(UC_HOOK_MEM_READ, hook_mem_read, mnt)
    print("before lev")
    
    result = XGorgen.leviathan(emulator, n, arr)
    print(''.join(['%02x' % b for b in result]))

    with open("./mem-mnt-dy8.txt", "w") as f:
        mnt.dump_read_no_write(f)
    #
except UcError as e:
    print("Exit at 0x%08X" % emulator.mu.reg_read(UC_ARM_REG_PC))
    emulator.memory.dump_maps(sys.stdout)
    raise
