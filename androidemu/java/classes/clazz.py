from ..java_class_def import JavaClassDef
from ..java_field_def import JavaFieldDef
from ..java_method_def import java_method_def, JavaMethodDef

class Class(metaclass=JavaClassDef, jvm_name='java/lang/Class'):
    class_loader = None
    def __init__(self, jvm_name):
        self.__jvm_name = jvm_name
    #

    @java_method_def(name='getClassLoader', signature='()Ljava/lang/ClassLoader;', native=False)
    def getClassLoader(self, emu):
        return Class.class_loader
    #
#
