from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_field_def import JavaFieldDef
from androidemu.java.java_method_def import java_method_def,JavaMethodDef


class Secure(metaclass=JavaClassDef, jvm_name='android/provider/Settings$Secure'):
    def __init__(self):
        pass
    #

    @staticmethod
    @java_method_def(name='getString', signature='(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;', native=False)
    def getPackageManager(emu, resolver, s1):
        raise NotImplementedError()
        return ""
    #
#


class Settings(metaclass=JavaClassDef, jvm_name='android/provider/Settings'):
    def __init__(self):
        pass
    #
#

