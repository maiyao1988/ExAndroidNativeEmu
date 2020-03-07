from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_field_def import JavaFieldDef
from androidemu.java.java_method_def import java_method_def,JavaMethodDef
from androidemu.java.classes.package_manager import PackageManager
from androidemu.java.classes.contentresolver import ContentResolver


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
#

class ContextImpl(Context, metaclass=JavaClassDef, jvm_name='android/app/ContextImpl', jvm_super=Context):
    def __init__(self):
        Context.__init__(self)
        self.__pkg_mgr = PackageManager()
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
#