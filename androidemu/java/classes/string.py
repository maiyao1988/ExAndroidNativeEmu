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

    @java_method_def(name='getBytes', args_list=["jstring"], signature='(Ljava/lang/String;)[B', native=False)
    def getBytes(self, emu, charset):
        print(charset)
        raise NotImplementedError()
    #

    def __repr__(self):
        return "JavaString(%s)"%self.get_py_string()
#