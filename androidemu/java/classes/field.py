from ..java_class_def import JavaClassDef
from ..java_field_def import JavaFieldDef
from ..java_method_def import java_method_def, JavaMethodDef
import logging

class AccessibleObject(metaclass=JavaClassDef, jvm_name='java/lang/reflect/AccessibleObject'):
    
    def __init__(self):
        pass
    #

    @java_method_def(name='setAccessible', args_list=["jboolean"], signature='(Z)V', native=False)
    def setAccessible(self, emu, access):
        logging.debug("AccessibleObject setAccessible call skip")
    #
#

class Field(AccessibleObject, metaclass=JavaClassDef, jvm_name='java/lang/reflect/Field', jvm_super=AccessibleObject):
    
    def __init__(self, pydeclaringClass: JavaClassDef, fieldName : str):
        super().__init__()
        self.__fieldName = fieldName
        self.declaringClass = pydeclaringClass
    #


    @java_method_def(name='get', args_list=["jobject"], signature='(Ljava/lang/Object;)Ljava/lang/Object;', native=False)
    def get(self, emu, obj):
        logging.debug("Field.get(%r)"%obj)

        v = getattr(obj, self.__fieldName)
        return v
    #
#
