from ..java_class_def import JavaClassDef
from ..java_field_def import JavaFieldDef
from ..java_method_def import java_method_def, JavaMethodDef
import logging
logger = logging.getLogger(__name__)

class DexFile(metaclass=JavaClassDef, jvm_name='dalvik/system/DexFile'):
    
    def __init__(self):
        pass
    #

    @java_method_def(name='<init>', args_list=["jstring"], signature='(Ljava/lang/String;)V', native=False)
    def ctor(self, emu, *args, **kwargs):
        logger.info("DexFile_ctor %r"%args)
        return DexFile()
    #
#
