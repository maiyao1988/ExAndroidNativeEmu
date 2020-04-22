from ..java_class_def import JavaClassDef
from ..java_field_def import JavaFieldDef
from ..java_method_def import java_method_def,JavaMethodDef
from ..constant_values import *


class List(metaclass=JavaClassDef, jvm_name='java/util/List'):
    def __init__(self, pylist):
        self.__pylist = pylist
    #

    def __len__(self):
        return len(self.__pylist)
    #

    def __getitem__(self,index):
        return self.__pylist[index]
    #

    def __setitem__(self,index,value):
        self.__pylist[index] = value
    #

    @java_method_def(name='get', signature='(I)Ljava/lang/Object;', native=False)
    def get(self, emu, index):
        if (index < len(self.__pylist)):
            return self.__pylist[index]
        return JAVA_NULL
    #


    @java_method_def(name='size', signature='()I', native=False)
    def size(self, emu):
        return len(self.__pylist)
    #
#

