from ..java_class_def import JavaClassDef
from ..java_field_def import JavaFieldDef
from ..java_method_def import java_method_def, JavaMethodDef
from ..classes.file import File
from ..classes.string import String

class Environment(metaclass=JavaClassDef, jvm_name='android/os/Environment'):
    
    def __init__(self):
        pass
    #

    @staticmethod
    @java_method_def(name='getExternalStorageDirectory', signature='()Ljava/io/File;', native=False)
    def getExternalStorageDirectory(emu):
        return File(String("/sdcard/"))
    #
#