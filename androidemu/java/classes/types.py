from ..java_class_def import JavaClassDef
from ..java_field_def import JavaFieldDef
from ..java_method_def import java_method_def, JavaMethodDef
from ...utils import debug_utils
import sys

class Boolean(metaclass=JavaClassDef, jvm_name='java/lang/Boolean'):
    
    def __init__(self, value=False):
        self.__value = value
    #

    @java_method_def(name='booleanValue', signature='()Z', native=False)
    def booleanValue(self, emu):
        return self.__value
    #

    def __repr__(self):
        return "%r"%self.__value
    #

    #TODO: 在继承多态机制完善后移动到Object类上
    @java_method_def(name='getClass', signature='()Ljava/lang/Class;', native=False)
    def getClass(self, emu):
        return self.class_object
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

    def __repr__(self):
        return "%r"%self.__value
    #

    #TODO: 在继承多态机制完善后移动到Object类上
    @java_method_def(name='getClass', signature='()Ljava/lang/Class;', native=False)
    def getClass(self, emu):
        return self.class_object
    #
#

class Long(metaclass=JavaClassDef, jvm_name='java/lang/Long'):
    
    def __init__(self, value=0):
        self.__value = value
    #

    @java_method_def(name='<init>', args_list=["jlong"], signature='(J)V', native=False)
    def ctor(self, emu, lvalue):

        self.__value = lvalue
    #

    @java_method_def(name='longValue', signature='()J', native=False)
    def longValue(self, emu):
        return self.__value
    #

    def __repr__(self):
        return "%r"%self.__value
    #    
    
    #TODO: 在继承多态机制完善后移动到Object类上
    @java_method_def(name='getClass', signature='()Ljava/lang/Class;', native=False)
    def getClass(self, emu):
        return self.class_object
    #

    def get_py_value(self):
        return self.__value
    #
#



class Float(metaclass=JavaClassDef, jvm_name='java/lang/Float'):
    
    def __init__(self, value=0.0):
        self.__value = value
    #

    def __repr__(self):
        return "%r"%self.__value
    #
    
    # #TODO: 在继承多态机制完善后移动到Object类上
    @java_method_def(name='getClass', signature='()Ljava/lang/Class;', native=False)
    def getClass(self, emu):
        return self.class_object
    #
#

