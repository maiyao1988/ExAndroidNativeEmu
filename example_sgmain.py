import logging
import posixpath
import sys
import os

from unicorn import *
from unicorn.arm_const import *

from androidemu.emulator import Emulator
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_method_def import java_method_def
from androidemu.java.classes.string import String
import androidemu.utils.debug_utils
from androidemu.utils.chain_log import ChainLogger
from androidemu.java.constant_values import *

import capstone
import traceback

g_cfd = ChainLogger(sys.stdout, "./ins-sgmain.txt")
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


class HttpUtil(metaclass=JavaClassDef, jvm_name='com/taobao/wireless/security/adapter/common/HttpUtil'):

    def __init__(self):
        pass

    @java_method_def(name='sendSyncHttpGetRequestBridge', signature='(Ljava/lang/String;)Ljava/lang/String;', native=False)
    def sendSyncHttpGetRequestBridge(self, mu, string):
        return JAVA_NULL
    #

    @java_method_def(name='sendSyncHttpPostRequestBridge', signature='(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;II)Ljava/lang/String;', native=False)
    def sendSyncHttpPostRequestBridge(self, mu, s1, s2, s3, i1, i2):
        return JAVA_NULL
    #

    @java_method_def(name='downloadFileBridge', signature='(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;', native=False)
    def downloadFileBridge(self, mu, s1, s2):
        return JAVA_NULL
    #
#


class UmidAdapter(metaclass=JavaClassDef, jvm_name='com/taobao/wireless/security/adapter/umid/UmidAdapter'):

    def __init__(self):
        pass

    @staticmethod
    @java_method_def(name='umidInitAdapter', signature='(I)I', native=False)
    def umidInitAdapter(mu, i1):
        return 0
    #
#


class JNICLibrary(metaclass=JavaClassDef, jvm_name='com/taobao/wireless/security/adapter/JNICLibrary'):

    def __init__(self):
        pass

    @staticmethod
    @java_method_def(name='doCommandNative', signature='(I[Ljava/lang/Object;)Ljava/lang/Object;', native=True)
    def doCommandNative(mu, i1, obj):
        pass
    #

#


class SPUtility2(metaclass=JavaClassDef, jvm_name='com/taobao/wireless/security/adapter/common/SPUtility2'):

    
    _kv = {}
    def __init__(self):
        pass
    #

    @staticmethod
    @java_method_def(name='readFromSPUnified', signature='(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;', native=False)
    def readFromSPUnified(mu, s1, s2, s3):
        return s3
    #

    @staticmethod
    @java_method_def(name='saveToFileUnifiedForNative', signature='(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)I', native=False)
    def saveToFileUnifiedForNative(mu, s1, s2, s3, b):
        return 0
    #

    @staticmethod
    @java_method_def(name='removeFromSPUnified', signature='(Ljava/lang/String;Ljava/lang/String;Z)Z', native=False)
    def removeFromSPUnified(mu, s1, s2, b):
        return True
    #

    @staticmethod
    @java_method_def(name='writeSS', signature='(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)Z', native=False)
    def writeSS(mu, ctx, s1, s2):
        _kv[s1] = s2
        return True
    #

    @staticmethod
    @java_method_def(name='readSS', signature='(Landroid/content/Context;Ljava/lang/String;)Ljava/lang/String;', native=False)
    def readSS(mu, ctx, s1):
        if (s1 in _kv):
            return _kv[s1]
        return String("")
    #

    @staticmethod
    @java_method_def(name='read', signature='(Ljava/lang/String;)Ljava/lang/String;', native=False)
    def read(mu, s1):
        if (s1 in _kv):
            return _kv[s1]
        return String("")
    #


    @staticmethod
    @java_method_def(name='write', signature='(Ljava/lang/String;Ljava/lang/String;)V', native=False)
    def write(mu, s1, s2):
        if (s1 in _kv):
            return _kv[s1]
        return String("")
    #
#

class DeviceInfoCapturer(metaclass=JavaClassDef, jvm_name='com/taobao/wireless/security/adapter/datacollection/DeviceInfoCapturer'):

    def __init__(self):
        pass

    @staticmethod
    @java_method_def(name='doCommandForString', signature='(I)Ljava/lang/String;', native=False)
    def doCommandForString(mu, cmdId):
        return String("0")
    #

#

class DataReportJniBridge(metaclass=JavaClassDef, jvm_name='com/taobao/wireless/security/adapter/datareport/DataReportJniBridge'):

    def __init__(self):
        pass

    @staticmethod
    @java_method_def(name='sendReportBridge', signature='(Ljava/lang/String;Ljava/lang/String;[B)Ljava/lang/String;', native=False)
    def sendReportBridge(mu, s1, s2, bytes1):
        return String("")
    #


    @staticmethod
    @java_method_def(name='accsAvaiableBridge', signature='()I', native=False)
    def accsAvaiableBridge(mu):
        return 1
    #


    @staticmethod
    @java_method_def(name='registerAccsListnerBridge', signature='()I', native=False)
    def registerAccsListnerBridge(mu):
        return 1
    #
#

class ZipUtils(metaclass=JavaClassDef, jvm_name='com/taobao/dp/util/ZipUtils'):

    def __init__(self):
        pass


    @staticmethod
    @java_method_def(name='unZip', signature='([B)[B', native=False)
    def unZip(mu, bytes):
        return 0
    #
#

class CallbackHelper(metaclass=JavaClassDef, jvm_name='com/taobao/dp/util/CallbackHelper'):

    def __init__(self):
        pass
    #

#

class UserTrackMethodJniBridge(metaclass=JavaClassDef, jvm_name='com/alibaba/wireless/security/framework/utils/UserTrackMethodJniBridge'):

    def __init__(self):
        pass
    #

    @staticmethod
    @java_method_def(name='utAvaiable', signature='()I', native=False)
    def utAvaiable(mu):
        return 0
    #

    @staticmethod
    @java_method_def(name='addUtRecord', signature='(Ljava/lang/String;IILjava/lang/String;JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I', native=False)
    def addUtRecord(mu):
        return 0
    #

    @staticmethod
    @java_method_def(name='getStackTrace', signature='(II)Ljava/lang/String;', native=False)
    def getStackTrace(mu):
        return 0
    #
#


logger = logging.getLogger(__name__)

# Initialize emulator
emulator = Emulator(
    vfs_root=posixpath.join(posixpath.dirname(__file__), "vfs")
)

# Register Java class.
emulator.java_classloader.add_class(HttpUtil)
emulator.java_classloader.add_class(UmidAdapter)
emulator.java_classloader.add_class(JNICLibrary)
emulator.java_classloader.add_class(SPUtility2)
emulator.java_classloader.add_class(DeviceInfoCapturer)

emulator.java_classloader.add_class(DataReportJniBridge)

emulator.java_classloader.add_class(ZipUtils)

emulator.java_classloader.add_class(CallbackHelper)

emulator.java_classloader.add_class(UserTrackMethodJniBridge)

# Load all libraries.
lib_module = emulator.load_library("tests/bin/libsgmainso-5.4.38.so")

#androidemu.utils.debug_utils.dump_symbols(emulator, sys.stdout)

# Show loaded modules.
logger.info("Loaded modules:")

for module in emulator.modules:
    logger.info("=> 0x%08x - %s" % (module.base, module.filename))

#emulator.mu.hook_add(UC_HOOK_CODE, hook_code, emulator)

try:
    # Run JNI_OnLoad.
    #   JNI_OnLoad will call 'RegisterNatives'.
    emulator.call_symbol(lib_module, 'JNI_OnLoad', emulator.java_vm.address_ptr, 0x00)

except UcError as e:
    print("Exit at %x" % emulator.mu.reg_read(UC_ARM_REG_PC))
    raise

