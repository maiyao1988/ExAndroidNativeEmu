from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_field_def import JavaFieldDef
from androidemu.java.java_method_def import java_method_def, JavaMethodDef
from androidemu.java.classes.string import String

class NetworkInterface(metaclass=JavaClassDef, jvm_name='java/net/NetworkInterface'):
    def __init__(self):
        pass
    #

    @staticmethod
    @java_method_def(name='getByName', args_list=["jstring"], signature='(Ljava/lang/String;)Ljava/net/NetworkInterface;', native=False)
    def getByName(emu, s1):
        print("getByName %r"%s1)
        raise NotImplementedError()
    #
#