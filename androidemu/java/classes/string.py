from ..java_class_def import JavaClassDef
from ..java_field_def import JavaFieldDef
from ..java_method_def import java_method_def, JavaMethodDef
from .array import *

class String(metaclass=JavaClassDef, jvm_name='java/lang/String'):
    
    def __init__(self, pystr=""):
        assert type(pystr) == str
        self.__str = pystr
    #

    def get_py_string(self):
        return self.__str
    #

    @java_method_def(name='<init>', args_list=["jobject", "jstring"], signature='([BLjava/lang/String;)V', native=False)
    def ctor(self, emu, barr, charset):
        #print("%r %r"%(barr, charset))
        pyarr =barr.get_py_items()
        pystr = charset.get_py_string()
        self.__str = pyarr.decode(pystr)
        #print(self.__str)
    #

    @java_method_def(name='getBytes', args_list=["jstring"], signature='(Ljava/lang/String;)[B', native=False)
    def getBytes(self, emu, charset):
        pycharset = charset.get_py_string()
        barr = bytearray(self.__str, pycharset)
        arr = ByteArray(barr)
        return arr
    #

    def __repr__(self):
        return "JavaString(%s)"%self.get_py_string()
    #


    # #TODO: 在继承多态机制完善后移动到Object类上
    @java_method_def(name='getClass', signature='()Ljava/lang/Class;', native=False)
    def getClass(self, emu):
        return self.class_object
    #
#