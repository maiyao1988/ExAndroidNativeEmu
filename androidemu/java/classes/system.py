from ..java_class_def import JavaClassDef
from ..java_field_def import JavaFieldDef
from ..java_method_def import java_method_def,JavaMethodDef
from ..constant_values import *
from .string import String

class System(metaclass=JavaClassDef, jvm_name='java/lang/System'):

    def __init__(self):
        pass
    #

    @staticmethod
    @java_method_def(name='getProperty', args_list=["jstring"], signature='(Ljava/lang/String;)Ljava/lang/String;', native=False)
    def getProperty(mu, s1):
        key = s1.get_py_string()
        #TODO 放到配置文件
        if (key == "java.vm.version"):
            #1.6.0 for 4.4
            #2.1.0 for 6.0
            return String("1.6.0")
        #
        return String("")
        raise NotImplementedError()
    #
#

