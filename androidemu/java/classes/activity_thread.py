from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_field_def import JavaFieldDef
from androidemu.java.java_method_def import java_method_def, JavaMethodDef
from androidemu.java.classes.contextimpl import ContextImpl

class ActivityThread(metaclass=JavaClassDef, jvm_name='android/app/ActivityThread'):

    def __init__(self):
        self.__context = ContextImpl()
    #

    @staticmethod
    @java_method_def(name='currentActivityThread', signature='()Landroid/app/ActivityThread;', native=False)
    def currentActivityThread(emu):
        return ActivityThread()
    #

    @java_method_def(name='getSystemContext', signature='()Landroid/app/ContextImpl;', native=False)
    def getSystemContext(self, emu):
        return self.__context
    #
#