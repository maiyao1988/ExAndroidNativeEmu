from ..java_class_def import JavaClassDef
from ..java_field_def import JavaFieldDef
from ..java_method_def import java_method_def,JavaMethodDef
from ..constant_values import *
from .array import *


class Set(metaclass=JavaClassDef, jvm_name='java/util/Set'):
    def __init__(self, pyset):
        self.__pyset = pyset
    #

    @java_method_def(name='<init>', signature='()V', native=False)
    def ctor(self, emu):
        self.__pyset = set()
    #

    def __len__(self):
        return len(self.__pyset)
    #

    def __getitem__(self,key):
        return self.__pyset[key]
    #

    '''
    @java_method_def(name='get', args_list=["jobject"], signature='(Ljava/lang/Object;)Ljava/lang/Object;', native=False)
    def get(self, emu, key):
        if (key in self.__pyset):
            return self.__pyset[key]
        return JAVA_NULL
    #


    @java_method_def(name='put', args_list=["jobject", "jobject"], signature='(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;', native=False)
    def get(self, emu, key, value):
        prev = JAVA_NULL
        if (key in self.__pyset):
            prev = self.__pyset[key]
        #
        self.__pyset[key] = value
        return prev
    #
    '''

    @java_method_def(name='toArray', signature='()[Ljava/lang/Object;', native=False)
    def toArray(self, emu):
        return Array(list(self.__pyset))
    #


    @java_method_def(name='size', signature='()I', native=False)
    def size(self, emu):
        return len(self.__pyset)
    #
#