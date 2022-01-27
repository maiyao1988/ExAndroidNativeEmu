from .bundle import Bundle
from ..java_class_def import JavaClassDef
from ..java_field_def import JavaFieldDef
from ..java_method_def import java_method_def, JavaMethodDef


class IntentFilter(metaclass=JavaClassDef, jvm_name='android/content/IntentFilter'):

    def __init__(self):
        pass

    #


    @java_method_def(name='<init>', args_list=["jstring"], signature='(Ljava/lang/String;)V', native=False)
    def init(self, emu, str):
        pass

    #

#

class Intent(metaclass=JavaClassDef, jvm_name='android/content/Intent'):

    def __init__(self):
        pass

    #

    @java_method_def(name='getExtras', signature='()Landroid/os/Bundle;', native=False)
    def getExtras(self, emu):
        return Bundle()

    #


#