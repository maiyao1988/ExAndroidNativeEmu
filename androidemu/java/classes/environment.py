from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_field_def import JavaFieldDef
from androidemu.java.java_method_def import java_method_def, JavaMethodDef
from androidemu.java.classes.file import File

class Environment(metaclass=JavaClassDef, jvm_name='android/os/Environment'):
    
    def __init__(self):
        pass
    #

    @staticmethod
    @java_method_def(name='getExternalStorageDirectory', signature='()Ljava/io/File;', native=False)
    def getExternalStorageDirectory(emu):
        return File("/sdcard/")
    #
#