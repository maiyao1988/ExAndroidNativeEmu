from ..java_class_def import JavaClassDef
from ..java_field_def import JavaFieldDef
from ..java_method_def import java_method_def, JavaMethodDef
from .context import ContextImpl, Context, ContextWrapper


class Application(ContextWrapper, metaclass=JavaClassDef, jvm_name='android/app/Application'):

    def __init__(self):
        pass
    #
    
#