from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_field_def import JavaFieldDef
from androidemu.java.java_method_def import java_method_def, JavaMethodDef

class Uri(metaclass=JavaClassDef, jvm_name="android/net/Uri"):
    
    def __init__(self, pystr):
        self.__uri = pystr
    #

    @staticmethod
    @java_method_def(name='parse', args_list=["jstring"], signature='(Ljava/lang/String;)Landroid/net/Uri;', native=False)
    def parse(emu, uri):
        pystr_uri = uri.get_py_string()
        uri = Uri(pystr_uri)
        return uri
    #

#
