from..java_class_def import JavaClassDef
from..java_field_def import JavaFieldDef
from..java_method_def import java_method_def,JavaMethodDef
from .package_manager import *
from .contentresolver import ContentResolver
from .string import String
from ... import config

class Context(metaclass=JavaClassDef, jvm_name='android/content/Context',
                 jvm_fields=[
                     JavaFieldDef('WIFI_SERVICE', 'Ljava/lang/String;', True, "wifi")
                 ]):
    def __init__(self):
        pass
    #

    @java_method_def(name='getPackageManager', signature='()Landroid/content/pm/PackageManager;', native=False)
    def getPackageManager(self, emu):
        pass
    #

    @java_method_def(name='getContentResolver', signature='()Landroid/content/ContentResolver;', native=False)
    def getContentResolver(self, emu):
        pass
    #

    @java_method_def(name='getSystemService', signature='(Ljava/lang/String;)Ljava/lang/Object;', native=False)
    def getSystemService(self, emu, s1):
        pass
    #

    @java_method_def(name='getApplicationInfo', signature='()Landroid/content/pm/ApplicationInfo;', native=False)
    def getApplicationInfo(self, emu):
        pass
    #
#

class ContextImpl(Context, metaclass=JavaClassDef, jvm_name='android/app/ContextImpl', jvm_super=Context):
    def __init__(self):
        Context.__init__(self)

        pyPkgName = config.global_config_get("pkg_name")
        self.__pkgName = String(pyPkgName)
        self.__pkg_mgr = PackageManager(pyPkgName)
        self.__resolver = ContentResolver()
    #
    
    @java_method_def(name='getPackageManager', signature='()Landroid/content/pm/PackageManager;', native=False)
    def getPackageManager(self, emu):
        return self.__pkg_mgr
    #

    @java_method_def(name='getContentResolver', signature='()Landroid/content/ContentResolver;', native=False)
    def getContentResolver(self, emu):
        return self.__resolver
    #

    @java_method_def(name='getSystemService', signature='(Ljava/lang/String;)Ljava/lang/Object;', native=False)
    def getSystemService(self, emu, s1):
        print(s1)
        raise NotImplementedError()
    #

    @java_method_def(name='getApplicationInfo', signature='()Landroid/content/pm/ApplicationInfo;', native=False)
    def getApplicationInfo(self, emu):
        pkgMgr = self.__pkg_mgr
        pkgInfo = pkgMgr.getPackageInfo(emu)
        return pkgInfo.applicationInfo
    #

    @java_method_def(name='getPackageName', signature='()Ljava/lang/String;', native=False)
    def getPackageName(self, emu):
        return self.__pkgName
    #
#

class ContextWrapper(Context, metaclass=JavaClassDef, jvm_name='android/content/ContextWrapper', jvm_super=Context):
    
    def __init__(self):
        Context.__init__(self)
        self.__impl = None
    #

    def attachBaseContext(self, ctx_impl):
        self.__impl = ctx_impl
    #

    @java_method_def(name='getPackageManager', signature='()Landroid/content/pm/PackageManager;', native=False)
    def getPackageManager(self, emu):
        return self.__impl.getPackageManager(emu)
    #

    @java_method_def(name='getContentResolver', signature='()Landroid/content/ContentResolver;', native=False)
    def getContentResolver(self, emu):
        return self.__impl.getContentResolver(emu)
    #

    @java_method_def(name='getSystemService', signature='(Ljava/lang/String;)Ljava/lang/Object;', native=False)
    def getSystemService(self, emu, s1):
        return self.__impl.getSystemService(emu, s1)
    #

    @java_method_def(name='getApplicationInfo', signature='()Landroid/content/pm/ApplicationInfo;', native=False)
    def getApplicationInfo(self, emu):
        return self.__impl.getApplicationInfo(emu)
    #

    @java_method_def(name='getPackageName', signature='()Ljava/lang/String;', native=False)
    def getPackageName(self, emu):
        return self.__impl.getPackageName(emu)
    #
#