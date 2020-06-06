from ..java_class_def import JavaClassDef
from ..java_field_def import JavaFieldDef
from ..java_method_def import java_method_def, JavaMethodDef

class Boolean(metaclass=JavaClassDef, jvm_name='java/lang/Boolean'):
    
    def __init__(self, value=False):
        self.__value = value
    #

    @java_method_def(name='booleanValue', signature='()Z', native=False)
    def booleanValue(self, emu):
        return self.__value
    #

#


class Integer(metaclass=JavaClassDef, jvm_name='java/lang/Integer'):
    
    def __init__(self, value=0):
        self.__value = value
    #

    @java_method_def(name='<init>', args_list=["jint"], signature='(I)V', native=False)
    def ctor(self, emu, value):
        self.__value = value
    #

    @java_method_def(name='intValue', signature='()I', native=False)
    def intValue(self, emu):
        return self.__value
    #

#


class Float(metaclass=JavaClassDef, jvm_name='java/lang/Float'):
    
    def __init__(self, value=0.0):
        self.__value = value
    #

#

