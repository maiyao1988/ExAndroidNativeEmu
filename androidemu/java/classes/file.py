from ..java_class_def import JavaClassDef
from ..java_field_def import JavaFieldDef
from ..java_method_def import java_method_def, JavaMethodDef

class File(metaclass=JavaClassDef, jvm_name='java/io/File'):
    
    def __init__(self, path):
        self.__path = path
    #

    @java_method_def(name='getPath', signature='()Ljava/lang/String;', native=False)
    def getPath(self, emu):
        return self.__path
    #
#
