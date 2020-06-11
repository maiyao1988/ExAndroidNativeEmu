from ..java_class_def import JavaClassDef
from ..java_field_def import JavaFieldDef
from ..java_method_def import java_method_def, JavaMethodDef
from ..classes.context import ContextImpl
from .application import Application


class AccessibilityManager(metaclass=JavaClassDef, jvm_name='android/view/accessibility/AccessibilityManager'):
    def __init__(self):
        pass
    #

    @java_method_def(name='getEnabledAccessibilityServiceList', args_list=["jint"], signature='(I)Ljava/util/List;', native=False)
    def getEnabledAccessibilityServiceList(self, emu, i):
        raise NotImplementedError()
    #
#

class Window(metaclass=JavaClassDef, jvm_name='android/view/Window'):
    def __init__(self):
        self.__dec_view = View()
    #

    @java_method_def(name='getDecorView', signature='()Landroid/view/View;', native=False)
    def getDecorView(self, emu):
        return self.__dec_view
    #
#

class AttachInfo(metaclass=JavaClassDef, jvm_name='android/view/View$AttachInfo'):
    def __init__(self):
        pass
    #
#


class ViewRootImpl(metaclass=JavaClassDef, jvm_name='android/view/ViewRootImpl'):
    def __init__(self):
        pass
    #
#

class View(metaclass=JavaClassDef, jvm_name='android/view/View'):
    def __init__(self):
        pass
    #
#

class Activity(metaclass=JavaClassDef, jvm_name='android/app/Activity'):
    def __init__(self):
        self.__window = Window()
    #


    @java_method_def(name='getWindow', signature='()Landroid/view/Window;', native=False)
    def getWindow(self, emu):
        return self.__window
    #

    #这应该是Context的方法
    @java_method_def(name='getSystemService', signature='(Ljava/lang/String;)Ljava/lang/Object;', native=False)
    def getSystemService(self, emu):
        raise NotImplementedError()
    #
#


class ActivityClientRecord(metaclass=JavaClassDef, jvm_name='android/app/ActivityThread$ActivityClientRecord',
        jvm_fields=[
                     JavaFieldDef('paused', 'Z', False), 
                     JavaFieldDef('activity', 'Landroid/app/Activity;', False), 
                 ]):
    def __init__(self):
        self.paused = False
        self.activity = Activity()
    #
#

class ArrayMap(metaclass=JavaClassDef, jvm_name='android/util/ArrayMap'):
    def __init__(self, arr):
        self.__array = arr
    #

    @java_method_def(name='size', signature='()I', native=False)
    def size(self, emu):
        return len(self.__array)
    #

    @java_method_def(name='valueAt', args_list=["jint"], signature='(I)Ljava/lang/Object;', native=False)
    def valueAt(self, emu, id):
        return self.__array[id]
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
        #self.mActivities = ArrayMap([ActivityClientRecord()])
        self.mActivities = ArrayMap([])
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

