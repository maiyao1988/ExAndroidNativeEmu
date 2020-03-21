from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_field_def import JavaFieldDef
from androidemu.java.java_method_def import java_method_def,JavaMethodDef
from androidemu.java.classes.bundle import Bundle


class ContentResolver(metaclass=JavaClassDef, jvm_name='android/content/ContentResolver'):
    def __init__(self):
        pass
    #

    @java_method_def(name='getSystemService', signature='(Ljava/lang/String;)Ljava/lang/Object;', native=False)
    def getSystemService(self, emu):
        raise NotImplementedError()
    #

    @java_method_def(name='call', args_list=["jobject", "jstring", "jstring", "jobject"], \
        signature='(Landroid/net/Uri;Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)Landroid/os/Bundle;', native=False)
    def call(self, emu, uri, method, arg, extras):
        #FIXME how to implement uri=content://settings/system,method=GET_system,arg=__MTA_DEVICE_INFO__,extras=None ???
        print("%r %r %r %r"%(uri, method, arg, extras))
        pyuri_str = uri.get_py_string()
        py_method = method.get_py_string()
        py_arg = arg.get_py_string()
        if (pyuri_str == "content://settings/system" and py_method == "GET_system" and py_arg == "__MTA_DEVICE_INFO__"):
            return Bundle()
        #
        elif (pyuri_str == "content://settings/system" and py_method == "GET_secure" and py_arg == "android_id"):
            #aid taken from nexus5 android 4.4
            m = {"value":"39cc04a2ae83db0b"}
            return Bundle(m)
        #
        raise NotImplementedError()
    #
#
