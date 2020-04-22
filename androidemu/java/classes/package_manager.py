from ..java_class_def import JavaClassDef
from ..java_field_def import JavaFieldDef
from ..java_method_def import java_method_def, JavaMethodDef
from .string import String
import time


class ApplicationInfo(metaclass=JavaClassDef, jvm_name='android/content/pm/ApplicationInfo', 
jvm_fields=[
                     JavaFieldDef('sourceDir', 'Ljava/lang/String;', False),
                     JavaFieldDef('dataDir', 'Ljava/lang/String;', False),
                     JavaFieldDef('nativeLibraryDir', 'Ljava/lang/String;', False),
                     JavaFieldDef('flags', 'I', False),
                 ]):
    
    def __init__(self, pyPkgName):
        self.sourceDir = String("/data/app/%s/"%pyPkgName)
        self.dataDir = String("/data/data/%s"%pyPkgName)
        self.nativeLibraryDir = String("/data/data/%s"%pyPkgName)
        self.flags = 0x30e8bf46
    #

#

class PackageInfo(metaclass=JavaClassDef, jvm_name='android/content/pm/PackageInfo', 
jvm_fields=[
                     JavaFieldDef('applicationInfo', 'Landroid/content/pm/ApplicationInfo;', False),
                     JavaFieldDef('firstInstallTime', 'J', False),
                     JavaFieldDef('lastUpdateTime', 'J', False)                
                    ]):
    def __init__(self, pyPkgName):
        self.applicationInfo = ApplicationInfo(pyPkgName)
        self.firstInstallTime = int(time.time())
        self.lastUpdateTime = self.firstInstallTime
    #
#


class PackageManager(metaclass=JavaClassDef, jvm_name='android/content/pm/PackageManager'):
    def __init__(self, pyPkgName):
        self.__pkg_info = PackageInfo(pyPkgName)
    #

    @java_method_def(name='getPackageInfo', signature='(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;', native=False)
    def getPackageInfo(self, emu):
        return self.__pkg_info
    #
#
