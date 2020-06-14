import logging
import posixpath
import sys
import os
import json
import time
import traceback
import hashlib
import json
import urllib
import requests
import random

from unicorn import *
from unicorn.arm_const import *

from androidemu.emulator import Emulator
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_method_def import java_method_def
from androidemu.java.classes.string import String
from androidemu.java.classes.types import *
from androidemu.java.classes.context import *
from androidemu.java.classes.array import *
from androidemu.java.classes.map import *
from androidemu.java.classes.activity_thread import *
import androidemu.utils.debug_utils
from androidemu.utils.chain_log import ChainLogger
from androidemu.java.constant_values import *

from androidemu.vfs.virtual_file import VirtualFile
from androidemu.utils import misc_utils


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
        androidemu.utils.debug_utils.dump_code(emu, address, size, sys.stdout)
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
    @java_method_def(name='readFromSPUnified', args_list=["jstring", "jstring", "jstring"], signature='(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;', native=False)
    def readFromSPUnified(mu, s1, s2, s3):
        logger.debug("readFromSPUnified %s %s %s"%(s1, s2, s3))
        key = "%s_%s"%(s1.get_py_string(), s2.get_py_string())
        path = "vfs/data/data/fm.xiami.main/files/SGMANAGER_DATA2"
        with open(path) as f:
            content = f.read()
            js = json.loads(content)
            if key in js:
                print ("readFromSPUnified return %s"%js[key])
                return String(js[key])
            #
        #
        #raise NotImplementedError()
        return s3
    #

    @staticmethod
    @java_method_def(name='saveToFileUnifiedForNative', args_list=["jstring", "jstring", "jstring", "jboolean"], signature='(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)I', native=False)
    def saveToFileUnifiedForNative(mu, s1, s2, s3, b):
        logger.debug("saveToFileUnifiedForNative %s %s %s %r", s1, s2, s3, b)
        #raise NotImplementedError()
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
    @java_method_def(name='doCommandForString', args_list=["jint"], signature='(I)Ljava/lang/String;', native=False)
    def doCommandForString(mu, cmdId):
        print("doCommandForString %d"%cmdId)
        if (cmdId == 11):
            #http.proxy
            #有影响
            return String("0")
        elif (cmdId == 104):
            '''
            TelephonyManager v0 = h.a;
            if(v0 != null) {
                String v0_1 = v0.getDeviceId();
                if(v0_1 != null && v0_1.length() != 0) {
                    return v0_1;
                }
            }
            '''
            return JAVA_NULL
        #
        elif (cmdId == 105):
            #长度有影响
            #telephonyManager.getSubscriberId();
            #return String("12312321")
            return JAVA_NULL

        elif (cmdId == 109):
            #mac
            #有影响
            return String("00:a7:10:93:64:57")
        elif (cmdId == 110):
            #return v0.getSSID();
            return String("my-home")
        elif (cmdId == 111):
            #return v0.getBSSID();
            return String("78:bc:0a:3c:2c:81")
        elif (cmdId == 114):
            '''
            DisplayMetrics v0_1 = v0.getResources().getDisplayMetrics();
            int v1 = v0_1.widthPixels;
            int v0_2 = v0_1.heightPixels;
            '''
            return String("1080*1794")
        elif (cmdId == 115):
            #StatFs v1 = new StatFs(arg5.getPath());
            
            #long v2 = ((long)v1.getBlockSize());
            #long v0_1 = ((long)v1.getBlockCount());
            return String("11454181376")
        elif (cmdId == 117):
            '''
            Intent v8_2 = v8_1.registerReceiver(null, new IntentFilter("android.intent.action.BATTERY_CHANGED"));
            if(v8_2 == null) {
                goto label_67;
            }

            c.b = v8_2.getIntExtra("level", -1) + "";
            c.c = v8_2.getIntExtra("voltage", -1) + "";
            c.d = v8_2.getIntExtra("temperature", -1) + "";
            '''
            #有影响
            return String("100")
        elif (cmdId == 121):
            #v0 = Class.forName("com.taobao.login4android.Login").getMethod("getNick").invoke(v0);
            #goto label_10;
            #FIXME 对结果有影响
            return String("")
        #
        elif (cmdId == 122):
            return String("fm.xiami.main")
        elif (cmdId == 123):
            #v0.versionName
            #FIXME 对结果有影响
            return String("8.3.8")
        #
        else:
            raise NotImplementedError()
        #
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
        #raise NotImplementedError()
        #1 means ok
        logger.warn("utAvaiable just return 1")
        return 1
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
        logger.warn("registerAppLifeCyCleCallBack skip")
    #
#


class MainApplication(ContextWrapper, metaclass=JavaClassDef, jvm_name='fm/xiami/mainXiami/MainApplication', jvm_super=ContextWrapper):
    def __init__(self):
        pass
    #
#


class JNIBridge(metaclass=JavaClassDef, jvm_name='com/uc/crashsdk/JNIBridge'):

    def __init__(self):
        pass
    #

    @staticmethod
    @java_method_def(name='registerInfoCallback', args_list=["jstring", "jint", "jlong", "jint"], signature='(Ljava/lang/String;IJI)I', native=False)
    def registerInfoCallback(mu, s1, i1, j1, i2):
        logger.warn("registerInfoCallback %s skip..."%s1)
        return 0
    #
#


class SecException(metaclass=JavaClassDef, jvm_name='com/alibaba/wireless/security/open/SecException'):

    def __init__(self):
        pass
    #

    @java_method_def(name='<init>', args_list=["jstring", "jint"], signature='(Ljava/lang/String;I)V', native=False)
    def ctor(self, mu, s1, i1):
        logger.warning("SecException ctor %s %d ..."%(s1, i1))
    #
#

class SGPluginExtras(metaclass=JavaClassDef, jvm_name='com/alibaba/wireless/security/framework/SGPluginExtras', 
        jvm_fields=[
                     JavaFieldDef('slot', 'J', True, 0),
                 ]):

    def __init__(self):
        pass
    #
#

class MalDetect(metaclass=JavaClassDef, jvm_name='com/alibaba/wireless/security/securitybody/open/MalDetect'):

    def __init__(self):
        pass
    #

    @staticmethod
    @java_method_def(name='OnDetectionJNI', args_list=["jint", "jstring", "jstring"], signature='(ILjava/lang/String;Ljava/lang/String;)V', native=False)
    def OnDetectionJNI(mu, i1, s1, s2):
        logger.warning("OnDetectionJNI %d %s %s ..."%(i1, s1, s2))
        raise NotImplementedError()
    #
#



class NativeReflectUtils(metaclass=JavaClassDef, jvm_name='com/alibaba/wireless/security/securitybody/NativeReflectUtils'):

    def __init__(self):
        pass
    #

    @staticmethod
    @java_method_def(name='getScreenOrientation', args_list=["jint", "jstring", "jstring"], signature='(Landroid/content/Context;)I', native=False)
    def getScreenOrientation(mu, ctx):
        #竖屏
        return 1
    #
#

class SDKUtils(metaclass=JavaClassDef, jvm_name='mtopsdk/mtop/global/SDKUtils'):

    def __init__(self):
        pass
    #

    @staticmethod
    @java_method_def(name='getCorrectionTime', signature='()J', native=False)
    def getCorrectionTime(mu):
        return int(time.time())
        #just for not random debug
        #return 1591789191
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

def sgmain_init(emulator):

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
    emulator.java_classloader.add_class(MainApplication)
    emulator.java_classloader.add_class(JNIBridge)
    emulator.java_classloader.add_class(SecException)
    emulator.java_classloader.add_class(SGPluginExtras)
    emulator.java_classloader.add_class(MalDetect)
    emulator.java_classloader.add_class(NativeReflectUtils)
    emulator.java_classloader.add_class(SDKUtils)

    emulator.java_classloader.add_class(MiuiAd)
    emulator.java_classloader.add_class(TelephonyManagerEx)
    emulator.java_classloader.add_class(FtTelephonyAdapter)
    emulator.java_classloader.add_class(FtTelephony)
    emulator.java_classloader.add_class(FtDeviceInfo)
    emulator.java_classloader.add_class(ColorOSTelephonyManager)

    
    #map [vectors]
    path = "vfs/system/lib/vectors"
    vf = VirtualFile("[vectors]", misc_utils.my_open(path, os.O_RDONLY), path)
    emulator.memory.map(0xffff0000, 0x1000, UC_PROT_EXEC | UC_PROT_READ, vf, 0)


    # Load all libraries.
    lib_module = emulator.load_library("vfs/data/data/fm.xiami.main/lib/libsgmainso-6.4.163.so")
    lib_module_secbody = emulator.load_library("vfs/data/data/fm.xiami.main/lib/libsgsecuritybodyso-6.4.95.so")
    lib_module_avmp = emulator.load_library("vfs/data/data/fm.xiami.main/lib/libsgavmpso-6.4.35.so")


    # Show loaded modules.
    logger.info("Loaded modules:")

    for module in emulator.modules:
        logger.info("=> 0x%08x - %s" % (module.base, module.filename))
    #

    act_thread = ActivityThread()
    app = act_thread.currentApplication(emulator)

    emulator.call_symbol(lib_module, 'JNI_OnLoad', emulator.java_vm.address_ptr, 0x00)

    #10101 10102 sgmain
    o2 = Integer(1)
    o3 = String("")
    o4 = String("/data/data/fm.xiami.main/app_SGLib")
    o5 = String("")
    pyarr = [app, o2, o3, o4, o5]
    arr = Array(pyarr)
    #print(arr)

    JNICLibrary.doCommandNative(emulator, 10101, arr)

    o1 = String("main")
    o2 = String("6.4.163")
    o3 = String("/data/data/fm.xiami.main/lib/libsgmainso-6.4.163.so")
    
    print("begin 10102")
    arr = Array([o1, o2, o3])
    JNICLibrary.doCommandNative(emulator, 10102, arr)

    #10102 secbody
    print("secbody JNI_OnLoad")
    emulator.call_symbol(lib_module_secbody, 'JNI_OnLoad', emulator.java_vm.address_ptr, 0x00)
    
    o1 = String("securitybody")
    o2 = String("6.4.95")
    o3 = String("/data/data/fm.xiami.main/lib/libsgsecuritybodyso-6.4.95.so")
    
    print("begin securitybodyso 10102")
    arr = Array([o1, o2, o3])
    JNICLibrary.doCommandNative(emulator, 10102, arr)

    #10102 avmp
    emulator.call_symbol(lib_module_avmp, 'JNI_OnLoad', emulator.java_vm.address_ptr, 0x00)

    o1 = String("avmp")
    o2 = String("6.4.35")
    o3 = String("/data/data/fm.xiami.main/lib/libsgavmpso-6.4.35.so")

    print("begin avmp 10102")
    arr = Array([o1, o2, o3])
    JNICLibrary.doCommandNative(emulator, 10102, arr)
#

def get_x_sign(emulator, data_str):
    o1 = HashMap({String("INPUT"):String(data_str)})
    o2 = String("21465214")
    o3 = Integer(7)
    o4 = JAVA_NULL
    o5 = Boolean(True)
    arr = Array([o1, o2, o3, o4, o5])
    print("begin 10401")
    r = JNICLibrary.doCommandNative(emulator, 10401, arr)
    return r.get_py_string()
#

def get_mini_wua(emulator, unix_time):
        
    o1 = String(str(unix_time)) #unix 时间搓，变量
    o2 = String("21465214") #appID
    o3 = Integer(8)
    o4 = JAVA_NULL
    o5 = String("pageName=&pageId=")
    o6 = Integer(0)

    print("begin securitybodyso 20102")
    arr = Array([o1, o2, o3, o4, o5, o6])

    #emulator.mu.hook_add(UC_HOOK_CODE, hook_code, emulator)
    mini_wua = JNICLibrary.doCommandNative(emulator, 20102, arr)
    return mini_wua.get_py_string()
#

def avmp_wua_sgcipher_create(emulator):        
    o1 = String("mwua")
    o2 = String("sgcipher")

    print("begin avmp 60901")
    arr = Array([o1, o2])
    vmp_inst = JNICLibrary.doCommandNative(emulator, 60901, arr)
    return vmp_inst
#

def get_wua(emulator, vmp_inst, sdata):

    data = ByteArray(bytearray(sdata, "utf-8"))
    le = Integer(len(data))

    maybe_arr_out = ByteArray(bytearray())
    o1 = vmp_inst
    o2 = String("sign")
    o3 = ByteArray.class_object
    o4 = ByteArray([Integer(0), data, le, String(""), maybe_arr_out, Integer(0)])
    arr = Array([o1, o2, o3, o4])
    print("60902 run")
    #emulator.mu.hook_add(UC_HOOK_CODE, hook_code, emulator)
    wua_arr = JNICLibrary.doCommandNative(emulator, 60902, arr)
    wua = wua_arr.get_py_items()
    return wua.decode("utf-8")
#

logger = logging.getLogger(__name__)

def test_enc():
    # Initialize emulator
    emulator = Emulator(
        vfs_root=posixpath.join(posixpath.dirname(__file__), "vfs"),
        config_path="xiami.json"
    )
    try:
        sgmain_init(emulator)

        '''
        01-26 02:46:31.968  5752  6060 I librev-dj: param0 {INPUT=XtX3M1bJ69cDAFWqkBwQYXgY&&&21465214&a75c08d1bc5069534cd65d35372bede2&2169991&mtop.alimusic.common.menuservice.getdata&1.0&&701287@xiami_android_8.3.8&AohsPSPH-F7lQLJzyIvh_6geqxEqIetYwOxZ0laI9k_9&&&27} [class java.util.HashMap]
        01-26 02:46:31.968  5752  6060 I librev-dj: param1 21465214 [class java.lang.String]
        01-26 02:46:31.968  5752  6060 I librev-dj: param2 7 [class java.lang.Integer]
        01-26 02:46:31.968  5752  6060 I librev-dj: param3 is null
        01-26 02:46:31.968  5752  6060 I librev-dj: param4 true [class java.lang.Boolean]
        01-26 02:46:31.976  5752  6060 I librev-dj: call my_doCommandNative return 0x200041
        01-26 02:46:31.976  5752  6060 I librev-dj: cmd 10401 return ab210e00103f3622607853182fe77adf41d41e872523ccfda2

        06-04 03:14:19.257  5796  6311 I librev-dj: call my_doCommandNative 10401
        06-04 03:14:19.258  5796  6311 I librev-dj: param0 {INPUT=XtX3M1bJ69cDAFWqkBwQYXgY&&&21465214&94de0d14487a78f08caa8b9366df870e&1591240459&mtop.alimusic.search.searchservice.searchsongs&1.3&&701287@xiami_android_8.3.8&AohsPSPH-F7lQLJzyIvh_6geqxEqIetYwOxZ0laI9k_9&&&27}
        06-04 03:14:19.258  5796  6311 I librev-dj: param1 21465214
        06-04 03:14:19.258  5796  6311 I librev-dj: param2 7
        06-04 03:14:19.258  5796  6311 I librev-dj: param3 is null
        06-04 03:14:19.258  5796  6311 I librev-dj: param4 true06-04 03:14:19.264  5796  6311 I librev-dj: call my_doCommandNative return 0x41
        06-04 03:14:19.264  5796  6311 I librev-dj: cmd 10401 return ab210e0010e507dbe03e3a648e23f5fa221b65a7a1cd01789e

        '''
        #s = "XtX3M1bJ69cDAFWqkBwQYXgY&&&21465214&a75c08d1bc5069534cd65d35372bede2&2169991&mtop.alimusic.common.menuservice.getdata&1.0&&701287@xiami_android_8.3.8&AohsPSPH-F7lQLJzyIvh_6geqxEqIetYwOxZ0laI9k_9&&&27"
        s = "XtX3M1bJ69cDAFWqkBwQYXgY&&&21465214&94de0d14487a78f08caa8b9366df870e&1591240459&mtop.alimusic.search.searchservice.searchsongs&1.3&&701287@xiami_android_8.3.8&AohsPSPH-F7lQLJzyIvh_6geqxEqIetYwOxZ0laI9k_9&&&27"
        r = get_x_sign(emulator, s)
        print("x-sign 10401 return %s"%r)
        '''    
        o1 = Integer(0)
        print("begin 12301")
        arr = Array([o1])
        r = JNICLibrary.doCommandNative(emulator, 12301, arr)
        '''

        mini_wua = get_mini_wua(emulator, 1591789191)
        print("mini_wua return %r"%mini_wua)

        vmp_inst = avmp_wua_sgcipher_create(emulator)
    
        print("60901 return %r"%vmp_inst)
        '''
        01-28 02:24:32.022  7389  7544 I librev-dj: call my_doCommandNative 60902
        01-28 02:24:32.022  7389  7544 I librev-dj: param0 4250478350 [class java.lang.Long]
        01-28 02:24:32.022  7389  7544 I librev-dj: param1 sign [class java.lang.String]
        01-28 02:24:32.022  7389  7544 I librev-dj: param2 class [B [class java.lang.Class]
        01-28 02:24:32.022  7389  7544 I librev-dj: param3 [Ljava.lang.Object;@800c770 [class [Ljava.lang.Object;]
        01-28 02:24:32.099  7389  7544 I librev-dj: call my_doCommandNative return 0x95
        01-28 02:24:32.099  7389  7544 I librev-dj: cmd 60902 return Udd9_PJaIv9t63ccPnqTEueflauoVQkhZLF+SWtD+hpI+ZvjblJMKz/9Ccp8oalFtHOHmE5MVXwGTzWDmtF8LRT2ssTpjnhXOvJfWH+hIAeqI3l0EVs3J5j7JjsoSvrrIQiUTJgjvOrSbNwQpEPB0hwYnTu82Aeuu03mJCFmuxfYc75ZVjqH1j4VLr81XTU/zmd1d9irWgA/mf2Ve512vxbj7qrW2Kuz8SUG3/bCNT2ta5ACJ1uZckEyv0ScQx8CynByYn41CQlrkHMT1mZgLM5Is6TfXE4UeC+pFLFuDXYta6ehiM49uflm95JQVBLwKezkOTjACWpol1B81p4Km+5wWFsMM62McPmgh2f31hgO4T8VpsY4DEdpsBKkrEfFUxmtt51Zy3G7Pw3NQRx823UWohZEV5veS2FFoU0pK+mmu2mGQHNLEE1Vbbxr1zA3uPTL0&MIT1_a0010fdb56926a9a642f4bd0f57dca86a9d50fcb85001
        01-28 02:24:32.099  7389  7544 I librev-dj: cmd 60902 inner array
        01-28 02:24:32.099  7389  7544 I librev-dj: param0 0 [class java.lang.Integer]
        01-28 02:24:32.099  7389  7544 I librev-dj: param1 [B@5b93ae9 [class [B]
        01-28 02:24:32.100  7389  7544 I librev-dj: param2 50 [class java.lang.Integer]
        01-28 02:24:32.100  7389  7544 I librev-dj: param3  [class java.lang.String]
        01-28 02:24:32.100  7389  7544 I librev-dj: param4 [B@907436e [class [B]
        01-28 02:24:32.100  7389  7544 I librev-dj: param5 0 [class java.lang.Integer]
        01-28 02:24:32.100  7389  7544 I librev-dj: cmd 60902 content ab210e0010e68383c6b1fe5baa33f0eddc45e943a955191a9a
        '''
        
        sdata = 'ab210e0010e68383c6b1fe5baa33f0eddc45e943a955191a9a'
        wua = get_wua(emulator, vmp_inst, sdata)
        print(wua)

    except UcError as e:
        print("Exit at 0x%08X" % emulator.mu.reg_read(UC_ARM_REG_PC))
        androidemu.utils.debug_utils.dump_registers(emulator.mu, sys.stdout)
        emulator.memory.dump_maps(sys.stdout)
        raise
    #
#

g_utdid = "XtX3M1bJ69cDAFWqkBwQYXgY"
#计数器初始值随机一下
g_countor = random.randint(123, 1221)
def _get_countor():
    global g_countor
    g_countor = (g_countor + 1) & 0x7fffffff
    return g_countor
#

def get_callId(api_perfix, serach_content, pageId):
    '''
    06-11 10:16:42.094  2572  3107 I Xposed  : digest input accessToken=platformId=android_phoneremoteIp=nullmodel={"isRecommendCorrection":true,"isTouFu":true,"key":"林俊杰","pagingVO":{"page":1,"pageSize":20}}ali88mu5sic
    06-11 10:16:42.094  2572  3107 I Xposed  : return [-127, 95, -59, -52, 49, -18, -72, -49, -77, 113, 52, -61, 47, 20, 20, 44]
    815fc5cc31eeb8cfb37134c32f14142c
    '''
    s = r'accessToken=platformId=android_phoneremoteIp=nullmodel={"isRecommendCorrection":true,"isTouFu":true,"key":"%s","pagingVO":{"page":%d,"pageSize":20}}ali88mu5sic'%(serach_content, pageId)
    #print(s)
    m = hashlib.md5()
    m.update(s.encode("utf-8"))
    #print(m.digest())
    return "%s_%s"%(api_perfix, m.hexdigest())
#

def get_x_c_traceid():
    global g_utdid
    ts = int(time.time()*1000)
    seq = _get_countor() % 10000
    processId = 4386 #暂时写死
    r = "%s%d%04d%s%d"%(g_utdid, ts, seq, "1", processId)
    return r
#

def gen_data(api, serach_content, page_id):
    callId = get_callId(api, serach_content, page_id)
    #注意一定要加r在前头，协议报文发出去就是要带\的
    data = r'{"requestStr":"{\"header\":{\"accessToken\":\"\",\"appId\":200,\"appVersion\":8030800,\"callId\":\"%s\",\"ch\":\"701287\",\"deviceId\":\"00c3476989d8b8a6\",\"language\":\"zh_CN\",\"network\":1,\"openId\":0,\"osVersion\":\"23\",\"platformId\":\"android_phone\",\"proxy\":\"false\",\"resolution\":\"1794x1080\",\"utdid\":\"%s\",\"uxid\":\"\"},\"model\":{\"isRecommendCorrection\":true,\"isTouFu\":true,\"key\":\"%s\",\"pagingVO\":{\"page\":%d,\"pageSize\":20}}}"}'\
    %(callId, g_utdid, serach_content, page_id)
    return data
#

def get_x_sign_input(api, data, unix_time):
    #最少校验header
    '''
    x-appkey: 21465214
    x-features: 27
    x-pv: 5.2
    x-t: 159193026
    x-ttid: 701287%40xiami_android_8.3.8
    x-utdid: XtX3M1bJ69cDAFWqkBwQYXgY
    x-devid: AohsPSPH-F7lQLJzyIvh_6geqxEqIetYwOxZ0laI9k_9
    x-sign: ab210e0010114a2aed193332437fe8317734f70a07698642ce
    '''
    m = hashlib.md5()
    m.update(data.encode("utf-8"))
    data_md5 = m.hexdigest()
    s = "%s&&&21465214&%s&%d&%s&1.3&&701287@xiami_android_8.3.8&AohsPSPH-F7lQLJzyIvh_6geqxEqIetYwOxZ0laI9k_9&&&27"\
        %(g_utdid, data_md5, unix_time, api)
    return s
#

def search_song(emulator, vmp_inst, serach_content):

    #test_enc()
    api = "mtop.alimusic.search.searchservice.searchsongs"
    #res = get_callId(api, serach_content, 1)
    #print(res)

    #x_c_traceid = get_x_c_traceid()
    #print(x_c_traceid)

    page_id = 1
    data = gen_data(api, serach_content, page_id)
    print(data)

    unix_time = int(time.time())
    x_sign_input = get_x_sign_input(api, data, unix_time)
    print(x_sign_input)
    
    #x_sign_input = "XtX3M1bJ69cDAFWqkBwQYXgY&&&21465214&9d2395108230634c7438d833739c4ec9&1591175586&mtop.alimusic.search.searchservice.searchsongs&1.3&&701287@xiami_android_8.3.8&AohsPSPH-F7lQLJzyIvh_6geqxEqIetYwOxZ0laI9k_9&&&27"
    #x_sign_input = "XtX3M1bJ69cDAFWqkBwQYXgY&&&21465214&b2604d60fe6fe6695f0c6e8186b9d972&1591887863&mtop.alimusic.search.searchservice.searchsongs&1.3&&701287@xiami_android_8.3.8&AohsPSPH-F7lQLJzyIvh_6geqxEqIetYwOxZ0laI9k_9&&&27"

    x_sign = get_x_sign(emulator, x_sign_input)
    print(x_sign)
    

    '''
    #必须的header
    x-appkey: 21465214
    x-features: 27
    x-pv: 5.2
    x-t: 159193026
    x-ttid: 701287%40xiami_android_8.3.8
    x-utdid: XtX3M1bJ69cDAFWqkBwQYXgY
    x-devid: AohsPSPH-F7lQLJzyIvh_6geqxEqIetYwOxZ0laI9k_9
    x-sign: ab210e0010114a2aed193332437fe8317734f70a07698642ce
    '''
    header = {}
    header["x-appkey"] = "21465214"
    header["x-nq"] = "WIFI"
    header["x-mini-wua"] = get_mini_wua(emulator, unix_time)
    header["x-c-traceid"] = get_x_c_traceid()
    header["x-app-conf-v"] = "0"
    header["x-features"] = "27"
    header["x-pv"] = "5.2"  #协议版本
    header["x-t"] = str(unix_time)
    header["x-app-ver"] = "8.3.8"
    header["f-refer"] = "mtop"
    header["user-agent"] = r"MTOPSDK%2F3.1.0.6+%28Android%3B6.0.1%3BLGE%3BAOSP+on+BullHead%29"
    header["x-ttid"] = r"701287%40xiami_android_8.3.8"
    header["x-nettype"] = "WIFI"
    header["cache-control"] = "no-cache"
    header["a-orange-q"] = "appKey=21465214&appVersion=8.3.8&clientAppIndexVersion=1120200603000600940&clientVersionIndexVersion=0"
    header["x-utdid"] = g_utdid
    header["x-umt"] = "pZ1LzvhLOlDOsjVyonOdfoph2Uetk1kT"
    header["x-devid"] = "AohsPSPH-F7lQLJzyIvh_6geqxEqIetYwOxZ0laI9k_9"
    header["x-sign"] = x_sign
    header["content-type"] = "application/x-www-form-urlencoded;charset=UTF-8"
    print("header:")
    print(header)
   
    url = "https://acs.m.taobao.com/gw/mtop.alimusic.search.searchservice.searchsongs/1.3/"
    #wua非必须
    #type非必须

    params_song = {"data":data,
      "wua" : get_wua(emulator, vmp_inst, x_sign),
      "type":"originaljson"}

    http_session = requests.Session()

    proxies = { "http": "http://127.0.0.1:8089", "https": "http://127.0.0.1:8089", } 
    r = http_session.get(url, headers=header, 
            params=params_song, verify=False
            #, proxies = proxies
            )
    resp = r.content
    return resp.decode("utf-8")
#

if __name__ == "__main__":
    emulator = Emulator(
        vfs_root=posixpath.join(posixpath.dirname(__file__), "vfs"),
        config_path="xiami.json"
    )
    sgmain_init(emulator)
    vmp_inst = avmp_wua_sgcipher_create(emulator)
    serach_content = "周杰伦"
    t1 = time.time()
    resp = search_song(emulator, vmp_inst, serach_content)
    t2 = time.time() - t1
    print(resp)
    print("time used %.3f"%t2)

    serach_content = "稻香"
    t1 = time.time()
    resp = search_song(emulator, vmp_inst, serach_content)
    t2 = time.time() - t1
    print(resp)
    print("time used %.3f"%t2)
#

