from ..java_class_def import JavaClassDef
from ..java_field_def import JavaFieldDef
from ..java_method_def import java_method_def, JavaMethodDef

class Field(metaclass=JavaClassDef, jvm_name='java/lang/reflect/Field'):
    
    def __init__(self):
        pass
    #

    @java_method_def(name='get', args_list=["jobject"], signature='(Ljava/lang/Object;)Ljava/lang/Object;', native=False)
    def get(self, emu, obj):
        raise NotImplementedError()
    #
#

class AccessibleObject(metaclass=JavaClassDef, jvm_name='java/lang/reflect/AccessibleObject'):
    
    def __init__(self):
        pass
    #

    @java_method_def(name='setAccessible', args_list=["jboolean"], signature='(Z)V', native=False)
    def setAccessible(self, emu, access):
        logger.debug("AccessibleObject setAccessible call skip")
    #
#