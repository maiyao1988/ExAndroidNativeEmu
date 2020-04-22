from ..java_class_def import JavaClassDef
from ..java_field_def import JavaFieldDef
from ..java_method_def import java_method_def, JavaMethodDef

class Debug(metaclass=JavaClassDef, jvm_name='android/os/Debug'):
    
    def __init__(self):
        pass
    #

    @staticmethod
    @java_method_def(name='isDebuggerConnected', signature='()Z', native=False)
    def isDebuggerConnected(emu):
        return False
    #
#