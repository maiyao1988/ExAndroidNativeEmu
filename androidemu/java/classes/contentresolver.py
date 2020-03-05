from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_field_def import JavaFieldDef
from androidemu.java.java_method_def import java_method_def,JavaMethodDef


class ContentResolver(metaclass=JavaClassDef, jvm_name='android/content/ContentResolver'):
    def __init__(self):
        pass
    #

    @java_method_def(name='getSystemService', signature='(Ljava/lang/String;)Ljava/lang/Object;', native=False)
    def getSystemService(self, emu):
        return self.__pkg_mgr
    #
#
