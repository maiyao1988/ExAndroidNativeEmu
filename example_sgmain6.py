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
from androidemu.java.classes.types import *
from androidemu.java.classes.context import *
from androidemu.java.classes.array import Array
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
        raise NotImplementedError()
        return ""
    #

    @java_method_def(name='sendSyncHttpPostRequestBridge', signature='(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;II)Ljava/lang/String;', native=False)
    def sendSyncHttpPostRequestBridge(self, mu, s1, s2, s3, i1, i2):
        raise NotImplementedError()
        return ""
    #

    @java_method_def(name='downloadFileBridge', signature='(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;', native=False)
    def downloadFileBridge(self, mu, s1, s2):
        raise NotImplementedError()
        return ""
    #
#


class UmidAdapter(metaclass=JavaClassDef, jvm_name='com/taobao/wireless/security/adapter/umid/UmidAdapter'):

    def __init__(self):
        pass

    @staticmethod
    @java_method_def(name='umidInitAdapter', signature='(I)I', native=False)
    def umidInitAdapter(mu, i1):
        raise NotImplementedError()
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
        raise NotImplementedError()
        return String("")
    #

    @staticmethod
    @java_method_def(name='sendReportBridgeHttps', signature='(Ljava/lang/String;Ljava/lang/String;[B)Ljava/lang/String;', native=False)
    def sendReportBridgeHttps(mu, s1, s2, bytes1):
        raise NotImplementedError()
        return String("")
    #

    @staticmethod
    @java_method_def(name='sendReportBridgeMtop', signature='(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;[B)Ljava/lang/String;', native=False)
    def sendReportBridgeMtop(mu, s1, s2, s3, map, bytes1):
        raise NotImplementedError()
        return String("")
    #

    @staticmethod
    @java_method_def(name='accsAvaiableBridge', signature='()I', native=False)
    def accsAvaiableBridge(mu):
        raise NotImplementedError()
        return 1
    #

    @staticmethod
    @java_method_def(name='mtopAvaiableBridge', signature='()I', native=False)
    def mtopAvaiableBridge(mu):
        raise NotImplementedError()
        return 1
    #

    @staticmethod
    @java_method_def(name='orangeAvailableBridge', signature='()I', native=False)
    def orangeAvailableBridge(mu):
        raise NotImplementedError()
        return 1
    #

    @staticmethod
    @java_method_def(name='registerAccsListnerBridge', signature='()I', native=False)
    def registerAccsListnerBridge(mu):
        raise NotImplementedError()
        return 1
    #

    @staticmethod
    @java_method_def(name='registerOrangeListenerBridge', signature='()I', native=False)
    def registerOrangeListenerBridge(mu):
        raise NotImplementedError()
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
        raise NotImplementedError()
        return 0
    #

    @staticmethod
    @java_method_def(name='addUtRecord', signature='(Ljava/lang/String;IILjava/lang/String;JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I', native=False)
    def addUtRecord(mu):
        raise NotImplementedError()
        return 0
    #

    @staticmethod
    @java_method_def(name='getStackTrace', signature='(II)Ljava/lang/String;', native=False)
    def getStackTrace(mu):
        raise NotImplementedError()
        return 0
    #
#


class UMIDComponent(metaclass=JavaClassDef, jvm_name='com/alibaba/wireless/security/open/umid/UMIDComponent'):

    def __init__(self):
        pass
    #

    @staticmethod
    @java_method_def(name='sendUmidChangedNotification', args_list=["jstring"], signature='(Ljava/lang/String;I)V', native=False)
    def sendUmidChangedNotification(mu, s1):
        raise NotImplementedError()
    #
#

class ECMiscInfo(metaclass=JavaClassDef, jvm_name='com/alibaba/wireless/security/open/edgecomputing/ECMiscInfo'):

    def __init__(self):
        pass
    #

    @staticmethod
    @java_method_def(name='getLastAppVersion', signature='()Ljava/lang/String;', native=False)
    def getLastAppVersion(mu):
        raise NotImplementedError()
        return String("1.0")
    #


    @staticmethod
    @java_method_def(name='getAppFirstRunState', signature='()Z', native=False)
    def getAppFirstRunState(mu):
        return True
    #

    @staticmethod
    @java_method_def(name='updateAppVersion', signature='(Ljava/lang/String;)V', native=False)
    def updateAppVersion(mu):
        pass
    #

    @staticmethod
    @java_method_def(name='updateAppFirstRunState', signature='()V', native=False)
    def updateAppFirstRunState(mu):
        pass
    #

    @staticmethod
    @java_method_def(name='registerAppLifeCyCleCallBack', signature='()V', native=False)
    def registerAppLifeCyCleCallBack(mu):
        raise NotImplementedError()
        pass
    #
#


class MainApplication(ContextWrapper, metaclass=JavaClassDef, jvm_name='fm/xiami/mainXiami/MainApplication', jvm_super=ContextWrapper):
    def __init__(self):
        pass
    #
#

#not exist in usual sdk!!!
class MiuiAd(metaclass=JavaClassDef, jvm_name='android/provider/MiuiSettings$Ad', jvm_ignore=True):

    def __init__(self):
        pass
    #

#


#not exist in usual sdk!!!
class MiuiAd(metaclass=JavaClassDef, jvm_name='android/provider/MiuiSettings$Ad', jvm_ignore=True):

    def __init__(self):
        pass
    #

#

#not exist in usual sdk!!!
class TelephonyManagerEx(metaclass=JavaClassDef, jvm_name='miui/telephony/TelephonyManagerEx', jvm_ignore=True):

    def __init__(self):
        pass
    #

#


#not exist in usual sdk!!!
class FtTelephonyAdapter(metaclass=JavaClassDef, jvm_name='android/telephony/FtTelephonyAdapter', jvm_ignore=True):

    def __init__(self):
        pass
    #

#


#not exist in usual sdk!!!
class FtTelephony(metaclass=JavaClassDef, jvm_name='android/telephony/FtTelephony', jvm_ignore=True):

    def __init__(self):
        pass
    #

#

#not exist in usual sdk!!!
class FtDeviceInfo(metaclass=JavaClassDef, jvm_name='android/util/FtDeviceInfo', jvm_ignore=True):

    def __init__(self):
        pass
    #

#

#not exist in usual sdk!!!
class ColorOSTelephonyManager(metaclass=JavaClassDef, jvm_name='android/telephony/ColorOSTelephonyManager', jvm_ignore=True):

    def __init__(self):
        pass
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
emulator.java_classloader.add_class(UMIDComponent)
emulator.java_classloader.add_class(ECMiscInfo)

emulator.java_classloader.add_class(MiuiAd)
emulator.java_classloader.add_class(TelephonyManagerEx)
emulator.java_classloader.add_class(FtTelephonyAdapter)
emulator.java_classloader.add_class(FtTelephony)
emulator.java_classloader.add_class(FtDeviceInfo)
emulator.java_classloader.add_class(ColorOSTelephonyManager)
emulator.java_classloader.add_class(MainApplication)

# Load all libraries.
lib_module = emulator.load_library("tests/bin/libsgmainso-6.4.163.so")

#androidemu.utils.debug_utils.dump_symbols(emulator, sys.stdout)

# Show loaded modules.
logger.info("Loaded modules:")

for module in emulator.modules:
    logger.info("=> 0x%08x - %s" % (module.base, module.filename))

#emulator.mu.hook_add(UC_HOOK_CODE, hook_code, emulator)
try:
    # Run JNI_OnLoad.
    #   JNI_OnLoad will call 'RegisterNatives'.
    impl = ContextImpl()
    emulator.call_symbol(lib_module, 'JNI_OnLoad', emulator.java_vm.address_ptr, 0x00)

    cmd = 10101
    app = MainApplication()
    app.attachBaseContext(impl)

    o2 = Integer(3)
    o3 = String("")
    o4 = String("/data/user/0/fm.xiami.main/app_SGLib")
    pyarr = [app, o2, o3, o4]
    arr = Array("[Ljava/lang/Object;", pyarr)
    #print(arr)

    JNICLibrary.doCommandNative(emulator, cmd, arr)


except UcError as e:
    print("Exit at %x" % emulator.mu.reg_read(UC_ARM_REG_PC))
    raise

