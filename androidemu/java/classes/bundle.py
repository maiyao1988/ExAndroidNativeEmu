from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_field_def import JavaFieldDef
from androidemu.java.java_method_def import java_method_def, JavaMethodDef
from androidemu.java.classes.string import String
from androidemu.java.constant_values import *

class Bundle(metaclass=JavaClassDef, jvm_name='android/os/Bundle'):
    
    def __init__(self, py_map = {}):
        self.__pymap = py_map
    #

    @java_method_def(name='getString', args_list=["jstring"], signature='(Ljava/lang/String;)Ljava/lang/String;', native=False)
    def getString(self, emu, k):
        pykey = k.get_py_string()
        if (pykey in self.__pymap):
            return String(self.__pymap[pykey])
        else:
            #attention do not return None, return None means no return value in function, return JAVA_NULL means the return value is NULL
            return JAVA_NULL
        #
        raise NotImplementedError()
    #
#