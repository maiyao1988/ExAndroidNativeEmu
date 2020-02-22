from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_field_def import JavaFieldDef
from androidemu.java.java_method_def import java_method_def, JavaMethodDef


class ApplicationInfo(metaclass=JavaClassDef, jvm_name='android/content/pm/ApplicationInfo', 
jvm_fields=[
                     JavaFieldDef('sourceDir', 'Ljava/lang/String;', False),
                     JavaFieldDef('dataDir', 'Ljava/lang/String;', False),
                     JavaFieldDef('nativeLibraryDir', 'Ljava/lang/String;', False)
                 ]):
    
    def __init__(self):
        self.sourceDir = "/data/app/com.myxh.coolshopping/"
        self.dataDir = "/data/data/com.myxh.coolshopping/"
        self.nativeLibraryDir = "/data/data/com.myxh.coolshopping/lib/"
    #
#

class PackageInfo(metaclass=JavaClassDef, jvm_name='android/content/pm/PackageInfo', 
jvm_fields=[
                     JavaFieldDef('applicationInfo', 'Landroid/content/pm/ApplicationInfo;', False)
                 ]):
    def __init__(self):
        self.applicationInfo = ApplicationInfo()
    #
#


class PackageManager(metaclass=JavaClassDef, jvm_name='android/content/pm/PackageManager'):
    def __init__(self):
        self.__pkg_info = PackageInfo()
    #

    @java_method_def(name='getPackageInfo', signature='(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;', native=False)
    def getPackageManager(self, emu):
        return self.__pkg_info
    #
#
