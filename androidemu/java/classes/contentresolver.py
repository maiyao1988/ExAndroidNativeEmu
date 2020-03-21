from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_field_def import JavaFieldDef
from androidemu.java.java_method_def import java_method_def,JavaMethodDef


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
    def call(self, emu, uri, s1, s2, bundle):
        #FIXME how to implement uri=content://settings/system,s1=GET_system,s2=__MTA_DEVICE_INFO__,bunle=None ???
        print("%r %r %r %r"%(uri, s1, s2, bundle))
        raise NotImplementedError()
    #
#
