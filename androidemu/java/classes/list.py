from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_field_def import JavaFieldDef
from androidemu.java.java_method_def import java_method_def,JavaMethodDef


class List(metaclass=JavaClassDef, jvm_name='java/util/List'):
    def __init__(self):
        self.__list = []
    #

    @java_method_def(name='get', signature='(I)Ljava/lang/Object;', native=False)
    def get(self, emu, index):
        if (index < len(self.__list)):
            return self.__list[index]
        return None
    #


    @java_method_def(name='size', signature='()I', native=False)
    def size(self, emu):
        return len(self.__list)
    #
#

