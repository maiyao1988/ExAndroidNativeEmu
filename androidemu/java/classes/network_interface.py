from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_field_def import JavaFieldDef
from androidemu.java.java_method_def import java_method_def, JavaMethodDef
from androidemu.java.classes.string import String
from androidemu.java.classes.array import Array
from androidemu import config

class NetworkInterface(metaclass=JavaClassDef, jvm_name='java/net/NetworkInterface'):
    def __init__(self, pyname):
        self.__name = pyname
    #

    @staticmethod
    @java_method_def(name='getByName', args_list=["jstring"], signature='(Ljava/lang/String;)Ljava/net/NetworkInterface;', native=False)
    def getByName(emu, s1):
        print("getByName %r"%s1)
        pyname = s1.get_py_string()
        return NetworkInterface(pyname)
    #

    @java_method_def(name='getHardwareAddress', signature='()[B', native=False)
    def getHardwareAddress(self, emu):
        mac = config.global_config_get("mac")
        barr = bytearray(mac)
        arr = Array("B", barr)
        return arr
    #
#