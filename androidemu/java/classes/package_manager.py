from ..java_class_def import JavaClassDef
from ..java_field_def import JavaFieldDef
from ..java_method_def import java_method_def, JavaMethodDef
from .string import String
from .array import ObjectArray, ByteArray
import time
import logging


class Signature(metaclass=JavaClassDef, jvm_name='android/content/pm/Signature'):

    def __init__(self, sign_hex):
        self.__sign_hex = sign_hex
    #


    @java_method_def(name='toByteArray', signature='()[B', native=False)
    def toByteArray(self, emu):
        #raise NotImplementedError()
        bs = bytes.fromhex(self.__sign_hex)
        #bs = b'abcd'
        return ByteArray(bytearray(bs))
    #

    @java_method_def(name='toCharsString', signature='()Ljava/lang/String;', native=False)
    def toCharsString(self, emu):
        return String(self.__sign_hex)
    #
#

class ApplicationInfo(metaclass=JavaClassDef, jvm_name='android/content/pm/ApplicationInfo', 
jvm_fields=[
                     JavaFieldDef('sourceDir', 'Ljava/lang/String;', False),
                     JavaFieldDef('dataDir', 'Ljava/lang/String;', False),
                     JavaFieldDef('nativeLibraryDir', 'Ljava/lang/String;', False),
                     JavaFieldDef('flags', 'I', False),
                 ]):
    
    def __init__(self, pyPkgName):
        self.sourceDir = String("/data/app/%s-1.apk"%pyPkgName)
        self.dataDir = String("/data/data/%s"%pyPkgName)
        self.nativeLibraryDir = String("/data/data/%s"%pyPkgName)
        self.flags = 0x30e8bf46
    #

#

class PackageInfo(metaclass=JavaClassDef, jvm_name='android/content/pm/PackageInfo', 
jvm_fields=[
                     JavaFieldDef('applicationInfo', 'Landroid/content/pm/ApplicationInfo;', False),
                     JavaFieldDef('firstInstallTime', 'J', False),
                     JavaFieldDef('lastUpdateTime', 'J', False),
                     JavaFieldDef('signatures', '[Landroid/content/pm/Signature;', False),
                     JavaFieldDef('versionCode', 'I', False),
                    ]):
    s_t = time.time()
    def __init__(self, pyPkgName, sign_hex, version_code):
        self.applicationInfo = ApplicationInfo(pyPkgName)
        self.firstInstallTime = int(PackageInfo.s_t)
        self.lastUpdateTime = self.firstInstallTime
        self.versionCode = version_code
        if (sign_hex):
            self.signatures = ObjectArray([Signature(sign_hex)])
        #
    #
#

#android中真正PackageManager是抽象类,真正实现类是ApplicationPackageManager,这里简化
class PackageManager(metaclass=JavaClassDef, jvm_name='android/content/pm/PackageManager', 
jvm_fields=[
                     JavaFieldDef('GET_SIGNATURES', 'I', True, 64),
                 ]):
    GET_SIGNATURES = 64
    def __init__(self, pyPkgName):
        self.__pyPkgName = pyPkgName
    #

    @java_method_def(name='getPackageInfo', args_list=["jstring", "jint"], signature='(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;', native=False)
    def getPackageInfo(self, emu, package_name, flags):
        #TODO 实现其他packageName 的 packageInfo
        if (package_name.get_py_string() != package_name.get_py_string()):
            raise NotImplementedError("not own package package-info not support now..")
        #
        sign_hex = emu.config.get("sign_hex", "0")
        if (flags == PackageManager.GET_SIGNATURES):
            if (sign_hex == "0"):
                raise RuntimeError("getPackageInfo with PackageManager.GET_SIGNATURES is called but no 'sign_hex' set in config!!!")
            #
        #
        version_code = emu.config.get("version_code")
        if (version_code == None):
            version_code = 0
            logging.info("version_code not config default to 0")
        #
        pkg_info = PackageInfo(self.__pyPkgName, sign_hex, version_code)
        return pkg_info
    #

    @java_method_def(name='checkPermission', args_list=["jstring", "jstring"], signature='(Ljava/lang/String;Ljava/lang/String;)I',native=False)
    def checkPermission(self, *args, **kwargs):
        #     PERMISSION_DENIED = -1;
        #     PERMISSION_GRANTED = 0;
        #print('Check Permission %s, %s' % (args[1], args[2]))
        return 0
    #
#
