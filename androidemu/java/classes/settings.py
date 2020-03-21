from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_field_def import JavaFieldDef
from androidemu.java.java_method_def import java_method_def,JavaMethodDef
from androidemu.java.classes.string import String


class Secure(metaclass=JavaClassDef, jvm_name='android/provider/Settings$Secure'):
    def __init__(self):
        pass
    #

    @staticmethod
    @java_method_def(name='getString', args_list=["jobject", "jstring"], signature='(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;', native=False)
    def getString(emu, resolver, s1):
        raise NotImplementedError()
        return String("")
    #
#


class Settings(metaclass=JavaClassDef, jvm_name='android/provider/Settings'):
    def __init__(self):
        pass
    #
#

