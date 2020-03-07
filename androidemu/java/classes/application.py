from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_field_def import JavaFieldDef
from androidemu.java.java_method_def import java_method_def, JavaMethodDef
from androidemu.java.classes.context import ContextImpl, Context, ContextWrapper


class Application(ContextWrapper, metaclass=JavaClassDef, jvm_name='android/app/Application'):

    def __init__(self):
        pass
    #
    
#