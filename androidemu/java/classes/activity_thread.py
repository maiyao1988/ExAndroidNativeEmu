from ..java_class_def import JavaClassDef
from ..java_field_def import JavaFieldDef
from ..java_method_def import java_method_def, JavaMethodDef
from ..classes.context import ContextImpl
from ..constant_values import *
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

class AccessibilityInteractionController(metaclass=JavaClassDef, jvm_name='android/view/AccessibilityInteractionController'):
    def __init__(self):
        pass
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

class ViewRootImpl(metaclass=JavaClassDef, jvm_name='android/view/ViewRootImpl',
                jvm_fields=[
                     JavaFieldDef('mAccessibilityInteractionController', 'android/view/AccessibilityInteractionController', False)
                 ]
    ):

    def __init__(self):
        self.mAccessibilityInteractionController = AccessibilityInteractionController()
    #
#

class AttachInfo(metaclass=JavaClassDef, jvm_name='android/view/View$AttachInfo', 
                jvm_fields=[
                     JavaFieldDef('mViewRootImpl', 'android/view/ViewRootImpl', False)
                 ]
    ):

    def __init__(self, view_root_impl):
        self.mViewRootImpl = view_root_impl
    #

#


class View(metaclass=JavaClassDef, jvm_name='android/view/View', 
                jvm_fields=[
                     JavaFieldDef('', 'android/view/View$AttachInfo', False)
                 ]
    ):
    def __init__(self):
        self.mAttachInfo = AttachInfo(ViewRootImpl())
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

class ActivityManager(metaclass=JavaClassDef, jvm_name='android/app/ActivityManager'):

    def __init__(self):
        pass
    #

    @staticmethod
    @java_method_def(name='isUserAMonkey', signature='()Z', native=False)
    def isUserAMonkey(emu):
        return False
    #
#


class IActivityManager(metaclass=JavaClassDef, jvm_name='android/app/IActivityManager'):

    def __init__(self):
        pass

    #

    @java_method_def(name='getClass', signature='()Ljava/lang/Class;', native=False)
    def getClass(self, emu):
        return self.class_object

    #
#


class ActivityManagerNative(metaclass=JavaClassDef, jvm_name='android/app/ActivityManagerNative'):

    def __init__(self):
        pass

    #

    @staticmethod
    @java_method_def(name='getDefault', signature='()android/app/IActivityManager;', native=False)
    def getDefault(emu):
        return IActivityManager()

    #
#

class Instrumentation(metaclass=JavaClassDef, jvm_name='android/app/Instrumentation'):

    def __init__(self):
        pass

    #

    @java_method_def(name='getClass', signature='()Ljava/lang/Class;', native=False)
    def getClass(self, emu):
        return self.class_object

    #
#

class IInterface(metaclass=JavaClassDef, jvm_name='android/os/IInterface'):
    def __init__(self):
        pass
    #
#

class IPackageManager(IInterface, metaclass=JavaClassDef, jvm_name='android/content/pm/IPackageManager', jvm_super=IInterface):
    def __init__(self):
        pass

    #
#


class ActivityThread(metaclass=JavaClassDef, jvm_name='android/app/ActivityThread', 
        jvm_fields=[
                     JavaFieldDef('mActivities', 'Landroid/util/ArrayMap;', False), 
                     #FIXME 多个虚拟机实例怎么办,作为静态对象,如何适应一个进程多个package name的情况?
                     JavaFieldDef('sPackageManager', 'Landroid/content/pm/IPackageManager;', True, IPackageManager()), 
        ]):

    s_am = {}
    def __init__(self, pyPkgName):
        self.__ctx_impl = ContextImpl(pyPkgName)
        self.app = Application()
        self.app.attachBaseContext(self.__ctx_impl)
        self.mActivities = ArrayMap([ActivityClientRecord()])
        self.mInstrumentation = Instrumentation()
        #self.mActivities = ArrayMap([])
    #

    @staticmethod
    @java_method_def(name='currentActivityThread', signature='()Landroid/app/ActivityThread;', native=False)
    def currentActivityThread(emu):
        pyPkgName = emu.config.get("pkg_name")
        if (pyPkgName not in ActivityThread.s_am):
            ActivityThread.s_am[pyPkgName] = ActivityThread(pyPkgName)
        #
        return ActivityThread.s_am[pyPkgName]
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

