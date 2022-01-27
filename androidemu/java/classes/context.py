from..java_class_def import JavaClassDef
from..java_field_def import JavaFieldDef
from..java_method_def import java_method_def,JavaMethodDef
from .package_manager import *
from .asset_manager import *
from .share_preference import *
from .wifi import TelephonyManager, WifiManager, ConnectivityManager
from .contentresolver import ContentResolver
from .string import String
from .file import File
from ... import config



class Context(metaclass=JavaClassDef, jvm_name='android/content/Context',
                 jvm_fields=[
                    JavaFieldDef('WIFI_SERVICE', 'Ljava/lang/String;', True, String("wifi")),
                    JavaFieldDef('TELEPHONY_SERVICE', 'Ljava/lang/String;', True, String("phone")),
                    JavaFieldDef('CONNECTIVITY_SERVICE', 'Ljava/lang/String;', True, String("connectivity"))
                 ]):
    def __init__(self):
        pass
    #

    @java_method_def(name='getPackageManager', signature='()Landroid/content/pm/PackageManager;', native=False)
    def getPackageManager(self, emu):
        raise RuntimeError("pure virtual function call!!!")
    #

    @java_method_def(name='getContentResolver', signature='()Landroid/content/ContentResolver;', native=False)
    def getContentResolver(self, emu):
        raise RuntimeError("pure virtual function call!!!")
    #

    @java_method_def(name='getSystemService', args_list=["jstring"], signature='(Ljava/lang/String;)Ljava/lang/Object;', native=False)
    def getSystemService(self, emu, s1):
        raise RuntimeError("pure virtual function call!!!")

    #

    @java_method_def(name='getApplicationInfo', signature='()Landroid/content/pm/ApplicationInfo;', native=False)
    def getApplicationInfo(self, emu):
        raise RuntimeError("pure virtual function call!!!")

    #

    @java_method_def(name='checkSelfPermission', signature='(Ljava/lang/String;)I', native=False)
    def checkSelfPermission(self, emu):
        raise RuntimeError("pure virtual function call!!!")

    #

    @java_method_def(name='checkCallingOrSelfPermission', signature='(Ljava/lang/String;)I', native=False)
    def checkCallingOrSelfPermission(self, emu):
        raise RuntimeError("pure virtual function call!!!")

    #

    @java_method_def(name='getPackageCodePath', signature='()Ljava/lang/String;', native=False)
    def getPackageCodePath(self, emu):
        raise RuntimeError("pure virtual function call!!!")

    #

    @java_method_def(name='getFilesDir', signature='()Ljava/io/File;', native=False)
    def getFilesDir(self, emu):
        raise RuntimeError("pure virtual function call!!!")

    #

    @java_method_def(name='getPackageName', signature='()Ljava/lang/String;', native=False)
    def getPackageName(self, emu):
        raise RuntimeError("pure virtual function call!!!")

    #

    @java_method_def(name='getSharedPreferences', args_list=["jstring", "jint"], signature='(Ljava/lang/String;I)Landroid/content/SharedPreferences;', native=False)
    def getSharedPreferences(self, emu, name, mode):
        raise RuntimeError("pure virtual function call!!!")
    #
#

class ContextImpl(Context, metaclass=JavaClassDef, jvm_name='android/app/ContextImpl', jvm_super=Context):
    def __init__(self, pyPkgName):
        Context.__init__(self)

        self.__pkgName = String(pyPkgName)
        self.__pkg_mgr = PackageManager(pyPkgName)
        self.__resolver = ContentResolver()
        self.__asset_mgr = None
        self.__sp_map = {}
    #
    
    @java_method_def(name='getPackageManager', signature='()Landroid/content/pm/PackageManager;', native=False)
    def getPackageManager(self, emu):
        return self.__pkg_mgr
    #

    @java_method_def(name='getAssets', signature='()Landroid/content/res/AssetManager;', native=False)
    def getAssets(self, emu):
        if (not self.__asset_mgr):
            #调用getAssets才初始化assert_manager
            #因为不是每个so模拟执行都需要打开apk
            pyapk_path = self.__pkg_mgr.getPackageInfo(emu, self.__pkgName, 0).applicationInfo.sourceDir.get_py_string()
            self.__asset_mgr = AssetManager(emu, pyapk_path)
        #
        return self.__asset_mgr
    #

    @java_method_def(name='getContentResolver', signature='()Landroid/content/ContentResolver;', native=False)
    def getContentResolver(self, emu):
        return self.__resolver
    #

    @java_method_def(name='getSystemService', args_list=["jstring"], signature='(Ljava/lang/String;)Ljava/lang/Object;', native=False)
    def getSystemService(self, emu, s1):
        print(s1)
        stype = s1.get_py_string()
        if stype == "phone":
            return TelephonyManager()
        #
        elif stype == "wifi":
            return WifiManager()
        #
        elif stype == "connectivity":
            return ConnectivityManager()
        #
        raise NotImplementedError()
    #

    @java_method_def(name='getApplicationInfo', signature='()Landroid/content/pm/ApplicationInfo;', native=False)
    def getApplicationInfo(self, emu):
        pkgMgr = self.__pkg_mgr
        pkgInfo = pkgMgr.getPackageInfo(emu, self.__pkgName, 0)
        return pkgInfo.applicationInfo
    #

    @java_method_def(name='getPackageName', signature='()Ljava/lang/String;', native=False)
    def getPackageName(self, emu):
        return self.__pkgName
    #

    @java_method_def(name='checkSelfPermission', signature='(Ljava/lang/String;)I', native=False)
    def checkSelfPermission(self, emu):
        return 0 #PERMISSION_GRANTED
    #

    @java_method_def(name='checkCallingOrSelfPermission', signature='(Ljava/lang/String;)I', native=False)
    def checkCallingOrSelfPermission(self, emu):
        return 0 #PERMISSION_GRANTED
    #

    @java_method_def(name='getPackageCodePath', signature='()Ljava/lang/String;', native=False)
    def getPackageCodePath(self, emu):
        pkgName = emu.config.get("pkg_name")
        path = "/data/app/%s-1.apk"%(pkgName, )
        return String(path)
    #

    @java_method_def(name='getFilesDir', signature='()Ljava/io/File;', native=False)
    def getFilesDir(self, emu):
        pkgName = emu.config.get("pkg_name")
        fdir = "/data/data/%s/files"%(pkgName, )
        return File(fdir)
    #

    @java_method_def(name='getSharedPreferences', args_list=["jstring", "jint"], signature='(Ljava/lang/String;I)Landroid/content/SharedPreferences;', native=False)
    def getSharedPreferences(self, emu, name, mode):
        pkgName = emu.config.get("pkg_name")
        pyName = name.get_py_string()
        if (pyName in self.__sp_map):
            return self.__sp_map[pyName]
        #
        else:
            path = "/data/data/%s/shared_prefs/%s.xml"%(pkgName, pyName)
            sp = SharedPreferences(emu, path)
            self.__sp_map[pyName] = sp
            return sp
        #
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

    @java_method_def(name='getAssets', signature='()Landroid/content/res/AssetManager;', native=False)
    def getAssets(self, emu):
        return self.__impl.getAssets(emu)
    #

    @java_method_def(name='getContentResolver', signature='()Landroid/content/ContentResolver;', native=False)
    def getContentResolver(self, emu):
        return self.__impl.getContentResolver(emu)
    #

    @java_method_def(name='getSystemService', args_list=["jstring"], signature='(Ljava/lang/String;)Ljava/lang/Object;', native=False)
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

    @java_method_def(name='checkSelfPermission', signature='(Ljava/lang/String;)I', native=False)
    def checkSelfPermission(self, emu):
        return self.__impl.checkSelfPermission(emu)
    #

    @java_method_def(name='checkCallingOrSelfPermission', signature='(Ljava/lang/String;)I', native=False)
    def checkCallingOrSelfPermission(self, emu):
        return self.__impl.checkCallingOrSelfPermission(emu)
    #

    @java_method_def(name='getPackageCodePath', signature='()Ljava/lang/String;', native=False)
    def getPackageCodePath(self, emu):
        return self.__impl.getPackageCodePath(emu)
    #

    @java_method_def(name='getFilesDir', signature='()Ljava/io/File;', native=False)
    def getFilesDir(self, emu):
        return self.__impl.getFilesDir(emu)
    #

    @java_method_def(name='getSharedPreferences', args_list=["jstring", "jint"], signature='(Ljava/lang/String;I)Landroid/content/SharedPreferences;', native=False)
    def getSharedPreferences(self, emu, name, mode):
        return self.__impl.getSharedPreferences(emu, name, mode)
    #
#