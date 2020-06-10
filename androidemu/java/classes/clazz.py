from ..java_class_def import JavaClassDef
from ..java_field_def import JavaFieldDef
from ..java_method_def import java_method_def, JavaMethodDef
from .string import *
from .method import *

class Class(metaclass=JavaClassDef, jvm_name='java/lang/Class'):
    class_loader = None
    def __init__(self, other_jvm_name):
        self.__descriptor_represent = other_jvm_name
    #

    @java_method_def(name='getClassLoader', signature='()Ljava/lang/ClassLoader;', native=False)
    def getClassLoader(self, emu):
        return Class.class_loader
    #

    @java_method_def(name='getName', signature='()Ljava/lang/String;', native=False)
    def getName(self, emu):
        name = self.__descriptor_represent
        assert name != None

        name = name.replace("/", ".")
        return String(name)
    #


    @java_method_def(name='getDeclaredMethod', args_list=["jstring", "jobject"], signature='(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;', native=False)
    def getDeclaredMethod(self, emu, name, parameterTypes):
        print("getDeclaredMethod name:[%r] parameterTypes:[%r]"%(name, parameterTypes))
        raise NotImplementedError()
    #


    def __repr__(self):
        return "Class(%s)"%self.__descriptor
    #
#
