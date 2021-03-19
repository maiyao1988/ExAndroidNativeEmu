from .jvm_id_conter import *
from .java_class_def import JavaClassDef

class JavaMethodDef:

    def __init__(self, func_name, func, name, signature, native, args_list=None, modifier=None, ignore=None):
        self.jvm_id = next_method_id()
        self.func_name = func_name
        self.func = func
        self.name = name
        self.signature = signature
        self.native = native
        self.native_addr = None
        self.args_list = args_list
        self.modifier = modifier
        self.ignore = ignore


def java_method_def(name, signature, native=False, args_list=None, modifier=None, ignore=False):
    def java_method_def_real(func):
        def native_wrapper(*args, **kwargs):
            clz = args[0].__class__
            emulator = None
            extra_args = None
            if (isinstance(clz, JavaClassDef) or isinstance(args[0], JavaClassDef)):
                #如果第一个参数是Java类对象，则是self 或者 如果第一个参数是Java类，则是cls
                emulator = args[1]
                thiz = args[0].jni_env_object_id
                extra_args = args[2:]
            #
            else:
                #否则是static方法
                emulator = args[0]
                thiz = 0x7FFFF
                extra_args = args[1:]
            #

            return emulator.call_native(
                native_wrapper.jvm_method.native_addr,
                emulator.java_vm.jni_env.address_ptr,  # JNIEnv*
                thiz,    # this, TODO: Implement proper "this", a reference to the Java object inside which this native
                         # method has been declared in
                *extra_args  # Extra args.
            )
        #
        def normal_wrapper(*args, **kwargs):
            result = func(*args, **kwargs)
            return result
        #
        wrapper = native_wrapper if native else normal_wrapper
        wrapper.jvm_method = JavaMethodDef(func.__name__, wrapper, name, signature, native,
                                           args_list=args_list,
                                           modifier=modifier,
                                           ignore=ignore)
        return wrapper
    #
    return java_method_def_real
#