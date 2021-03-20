import struct
from .jvm_id_conter import *
from .java_class_def import JavaClassDef
import logging
logger = logging.getLogger(__name__)

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

num_type_len = {"jlong": 8, "jint": 4, "jshort": 2, "jbyte": 1}
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

            # 转换基本类型为对应的int数值，处理负数、浮点数、8字节数
            new_extra_args = []
            if args_list and len(args_list) == len(extra_args):
                for i in range(len(extra_args)):
                    if isinstance(extra_args[i], int) and extra_args[i] < 0 and args_list[i] in ("jint", "jshort", "jbyte"):
                        b = extra_args[i].to_bytes(num_type_len[args_list[i]], byteorder='little', signed=True)
                        new_extra_args.append(int.from_bytes(b, byteorder='little', signed=False))
                    elif isinstance(extra_args[i], float) and args_list[i] == "jfloat":
                        b = struct.pack("<f", extra_args[i])
                        new_extra_args.append(int.from_bytes(b, byteorder='little', signed=False))
                    elif isinstance(extra_args[i], int) and args_list[i] == "jlong":
                        d = extra_args[i]
                        if extra_args[i] < 0:
                            b = extra_args[i].to_bytes(8, byteorder='little', signed=True)
                            d = int.from_bytes(b, byteorder='little', signed=False)
                        new_extra_args.append(d & 0xFFFFFFFF)
                        new_extra_args.append((d >> 32) & 0xFFFFFFFF)
                    elif isinstance(extra_args[i], float) and args_list[i] == "jdouble":
                        b = struct.pack("<d", extra_args[i])
                        d = int.from_bytes(b, byteorder='little', signed=False)
                        new_extra_args.append(d & 0xFFFFFFFF)
                        new_extra_args.append((d >> 32) & 0xFFFFFFFF)
                    else:
                        new_extra_args.append(extra_args[i])
            else:
                logger.warning("JNI func "+name+" "+signature+" parm not match. Don't use default value or key=parm.")
                new_extra_args = extra_args
            return_type = signature[signature.rfind(')')+1:]
            return emulator.call_native(
                native_wrapper.jvm_method.native_addr,
                return_type,
                emulator.java_vm.jni_env.address_ptr,  # JNIEnv*
                thiz,    # this, TODO: Implement proper "this", a reference to the Java object inside which this native
                         # method has been declared in
                *new_extra_args  # Extra args.
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