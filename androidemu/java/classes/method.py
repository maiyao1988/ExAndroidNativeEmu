import logging

from .executable import Executable
from ..java_class_def import JavaClassDef
from ..java_field_def import JavaFieldDef
from ..java_method_def import java_method_def, JavaMethodDef

logger = logging.getLogger(__name__)

class Method(metaclass=JavaClassDef,
             jvm_name='java/lang/reflect/Method',
             jvm_fields=[
                 JavaFieldDef('slot', 'I', False, ignore=True),
                 JavaFieldDef('declaringClass', 'Ljava/lang/Class;', False),
             ],
             jvm_super=Executable):

    def __init__(self, pydeclaringClass: JavaClassDef, pymethod: JavaMethodDef):
        super().__init__()
        self._method = pymethod
        self.slot = pymethod.jvm_id
        self.declaringClass = pydeclaringClass
        self.accessFlags = pymethod.modifier
    #

    @staticmethod
    @java_method_def(
        name="getMethodModifiers",
        signature="(Ljava/lang/Class;I)I",
        args_list=['jobject', 'jint']
    )
    def get_method_modifiers(emu, clazz_obj, jvm_method_id):
        clazz = clazz_obj.value
        method = clazz.find_method_by_id(jvm_method_id)

        logger.debug('get_method_modifiers(%s, %s)' % (clazz.jvm_name, method.name))

        if method.modifier is None:
            raise RuntimeError('No modifier was given to class %s method %s' % (clazz.jvm_name, method.name))

        return method.modifier
    #

    def __repr__(self):
        return "Method(%s, %s)"%(self.declaringClass, self._method)
    #
#
