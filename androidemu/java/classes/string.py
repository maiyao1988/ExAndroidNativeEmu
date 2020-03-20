from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_field_def import JavaFieldDef
from androidemu.java.java_method_def import java_method_def, JavaMethodDef

class String(metaclass=JavaClassDef, jvm_name='java/lang/String'):
    
    def __init__(self, pystr):
        self.__str = pystr
    #

    def get_py_string(self):
        return self.__str
    #
#