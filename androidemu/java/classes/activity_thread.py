from ..java_class_def import JavaClassDef
from ..java_field_def import JavaFieldDef
from ..java_method_def import java_method_def, JavaMethodDef
from ..classes.context import ContextImpl
from .application import Application

class ActivityThread(metaclass=JavaClassDef, jvm_name='android/app/ActivityThread'):

    s_am = None
    def __init__(self):
        self.__ctx_impl = ContextImpl()
        self.app = Application()
        self.app.attachBaseContext(self.__ctx_impl)
    #

    @staticmethod
    @java_method_def(name='currentActivityThread', signature='()Landroid/app/ActivityThread;', native=False)
    def currentActivityThread(emu):
        if (ActivityThread.s_am == None):
            ActivityThread.s_am = ActivityThread()
        #
        return ActivityThread.s_am
    #

    @staticmethod
    @java_method_def(name='currentApplication', signature='()Landroid/app/Application;', native=False)
    def currentApplication(emu):
        am = ActivityThread.currentActivityThread(emu)
        return am.app
    #

    @java_method_def(name='getSystemContext', signature='()Landroid/app/ContextImpl;', native=False)
    def getSystemContext(self, emu):
        return self.__ctx_impl
    #
#