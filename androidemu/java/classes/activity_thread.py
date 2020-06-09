from ..java_class_def import JavaClassDef
from ..java_field_def import JavaFieldDef
from ..java_method_def import java_method_def, JavaMethodDef
from ..classes.context import ContextImpl
from .application import Application

class ArrayMap(metaclass=JavaClassDef, jvm_name='android/util/ArrayMap'):
    def __init__(self):
        pass
    #

    @java_method_def(name='size', signature='()I', native=False)
    def size(self, emu):
        return 0
    #

    @java_method_def(name='valueAt', args_list=["jint"], signature='(I)Ljava/lang/Object;', native=False)
    def valueAt(self, emu, id):
        raise NotImplementedError()
    #
#

class ActivityThread(metaclass=JavaClassDef, jvm_name='android/app/ActivityThread', 
        jvm_fields=[
                     JavaFieldDef('mActivities', 'Landroid/util/ArrayMap;', False), 
        ]):

    s_am = None
    def __init__(self):
        self.__ctx_impl = ContextImpl()
        self.app = Application()
        self.app.attachBaseContext(self.__ctx_impl)
        self.mActivities = ArrayMap()
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


class ActivityClientRecord(metaclass=JavaClassDef, jvm_name='android/app/ActivityThread$ActivityClientRecord',
        jvm_fields=[
                     JavaFieldDef('paused', 'Z', False), 
                     JavaFieldDef('activity', 'Landroid/app/Activity;', False), 
                 ]):
    def __init__(self):
        self.paused = False
    #
#

