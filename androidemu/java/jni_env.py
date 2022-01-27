import logging
import sys

from ..hooker import Hooker
from .classes.constructor import Constructor
from .classes.method import Method
from .java_class_def import JavaClassDef
from .constant_values import MODIFIER_STATIC
from .helpers.native_method import native_method
from .jni_const import *
from .jni_ref import *
from .reference_table import ReferenceTable
from .classes.string import String
from .classes.array import Array
from .constant_values import JAVA_NULL
from ..utils import memory_helpers
from unicorn import *
from ..utils import debug_utils
from ..const import emu_const

logger = logging.getLogger(__name__)


# This class attempts to mimic the JNINativeInterface table.
class JNIEnv:
    """
    :type class_loader JavaClassLoader
    :type hooker Hooker
    """
    JNI_OK = 0
    def __init__(self, emu, class_loader, hooker):
        self._emu = emu
        self._class_loader = class_loader
        self._locals = ReferenceTable(start=1, max_entries=2048)
        self._globals = ReferenceTable(start=4096, max_entries=512000)
        arch = emu.get_arch()
        if (arch == emu_const.ARCH_ARM32):
            self.__read_args = self.__read_args32
            self.__read_args_v = self.__read_args_v32
        elif(arch == emu_const.ARCH_ARM64):
            self.__read_args = self.__read_args64
            self.__read_args_v = self.__read_args_v64
        else:
            raise NotImplementedError("unsupport arch %d"%arch)
        #

        (self.address_ptr, self.address) = hooker.write_function_table({
            4: self.get_version,
            5: self.define_class,
            6: self.find_class,
            7: self.from_reflected_method,
            8: self.from_reflected_field,
            9: self.to_reflected_method,
            10: self.get_superclass,
            11: self.is_assignable_from,
            12: self.to_reflected_field,
            13: self.throw,
            14: self.throw_new,
            15: self.exception_occurred,
            16: self.exception_describe,
            17: self.exception_clear,
            18: self.fatal_error,
            19: self.push_local_frame,
            20: self.pop_local_frame,
            21: self.new_global_ref,
            22: self.delete_global_ref,
            23: self.delete_local_ref,
            24: self.is_same_object,
            25: self.new_local_ref,
            26: self.ensure_local_capacity,
            27: self.alloc_object,
            28: self.new_object,
            29: self.new_object_v,
            30: self.new_object_a,
            31: self.get_object_class,
            32: self.is_instance_of,
            33: self.get_method_id,
            34: self.call_object_method,
            35: self.call_object_method_v,
            36: self.call_object_method_a,
            37: self.call_boolean_method,
            38: self.call_boolean_method_v,
            39: self.call_boolean_method_a,
            40: self.call_byte_method,
            41: self.call_byte_method_v,
            42: self.call_byte_method_a,
            43: self.call_char_method,
            44: self.call_char_method_v,
            45: self.call_char_method_a,
            46: self.call_short_method,
            47: self.call_short_method_v,
            48: self.call_short_method_a,
            49: self.call_int_method,
            50: self.call_int_method_v,
            51: self.call_int_method_a,
            52: self.call_long_method,
            53: self.call_long_method_v,
            54: self.call_long_method_a,
            55: self.call_float_method,
            56: self.call_float_method_v,
            57: self.call_float_method_a,
            58: self.call_double_method,
            59: self.call_double_method_v,
            60: self.call_double_method_a,
            61: self.call_void_method,
            62: self.call_void_method_v,
            63: self.call_void_method_a,
            64: self.call_nonvirtual_object_method,
            65: self.call_nonvirtual_object_method_v,
            66: self.call_nonvirtual_object_method_a,
            67: self.call_nonvirtual_boolean_method,
            68: self.call_nonvirtual_boolean_method_v,
            69: self.call_nonvirtual_boolean_method_a,
            70: self.call_nonvirtual_byte_method,
            71: self.call_nonvirtual_byte_method_v,
            72: self.call_nonvirtual_byte_method_a,
            73: self.call_nonvirtual_char_method,
            74: self.call_nonvirtual_char_method_v,
            75: self.call_nonvirtual_char_method_a,
            76: self.call_nonvirtual_short_method,
            77: self.call_nonvirtual_short_method_v,
            78: self.call_nonvirtual_short_method_a,
            79: self.call_nonvirtual_int_method,
            80: self.call_nonvirtual_int_method_v,
            81: self.call_nonvirtual_int_method_a,
            82: self.call_nonvirtual_long_method,
            83: self.call_nonvirtual_long_method_v,
            84: self.call_nonvirtual_long_method_a,
            85: self.call_nonvirtual_float_method,
            86: self.call_nonvirtual_float_method_v,
            87: self.call_nonvirtual_float_method_a,
            88: self.call_nonvirtual_double_method,
            89: self.call_nonvirtual_double_method_v,
            90: self.call_nonvirtual_double_method_a,
            91: self.call_nonvirtual_void_method,
            92: self.call_nonvirtual_void_method_v,
            93: self.call_nonvirtual_void_method_a,
            94: self.get_field_id,
            95: self.get_object_field,
            96: self.get_boolean_field,
            97: self.get_byte_field,
            98: self.get_char_field,
            99: self.get_short_field,
            100: self.get_int_field,
            101: self.get_long_field,
            102: self.get_float_field,
            103: self.get_double_field,
            104: self.set_object_field,
            105: self.set_boolean_field,
            106: self.set_byte_field,
            107: self.set_char_field,
            108: self.set_short_field,
            109: self.set_int_field,
            110: self.set_long_field,
            111: self.set_float_field,
            112: self.set_double_field,
            113: self.get_static_method_id,
            114: self.call_static_object_method,
            115: self.call_static_object_method_v,
            116: self.call_static_object_method_a,
            117: self.call_static_boolean_method,
            118: self.call_static_boolean_method_v,
            119: self.call_static_boolean_method_a,
            120: self.call_static_byte_method,
            121: self.call_static_byte_method_v,
            122: self.call_static_byte_method_a,
            123: self.call_static_char_method,
            124: self.call_static_char_method_v,
            125: self.call_static_char_method_a,
            126: self.call_static_short_method,
            127: self.call_static_short_method_v,
            128: self.call_static_short_method_a,
            129: self.call_static_int_method,
            130: self.call_static_int_method_v,
            131: self.call_static_int_method_a,
            132: self.call_static_long_method,
            133: self.call_static_long_method_v,
            134: self.call_static_long_method_a,
            135: self.call_static_float_method,
            136: self.call_static_float_method_v,
            137: self.call_static_float_method_a,
            138: self.call_static_double_method,
            139: self.call_static_double_method_v,
            140: self.call_static_double_method_a,
            141: self.call_static_void_method,
            142: self.call_static_void_method_v,
            143: self.call_static_void_method_a,
            144: self.get_static_field_id,
            145: self.get_static_object_field,
            146: self.get_static_boolean_field,
            147: self.get_static_byte_field,
            148: self.get_static_char_field,
            149: self.get_static_short_field,
            150: self.get_static_int_field,
            151: self.get_static_long_field,
            152: self.get_static_float_field,
            153: self.get_static_double_field,
            154: self.set_static_object_field,
            155: self.set_static_boolean_field,
            156: self.set_static_byte_field,
            157: self.set_static_char_field,
            158: self.set_static_short_field,
            159: self.set_static_int_field,
            160: self.set_static_long_field,
            161: self.set_static_float_field,
            162: self.set_static_double_field,
            163: self.new_string,
            164: self.get_string_length,
            165: self.get_string_chars,
            166: self.release_string_chars,
            167: self.new_string_utf,
            168: self.get_string_utf_length,
            169: self.get_string_utf_chars,
            170: self.release_string_utf_chars,
            171: self.get_array_length,
            172: self.new_object_array,
            173: self.get_object_array_element,
            174: self.set_object_array_element,
            175: self.new_boolean_array,
            176: self.new_byte_array,
            177: self.new_char_array,
            178: self.new_short_array,
            179: self.new_int_array,
            180: self.new_long_array,
            181: self.new_float_array,
            182: self.new_double_array,
            183: self.get_boolean_array_elements,
            184: self.get_byte_array_elements,
            185: self.get_char_array_elements,
            186: self.get_short_array_elements,
            187: self.get_int_array_elements,
            188: self.get_long_array_elements,
            189: self.get_float_array_elements,
            190: self.get_double_array_elements,
            191: self.release_boolean_array_elements,
            192: self.release_byte_array_elements,
            193: self.release_char_array_elements,
            194: self.release_short_array_elements,
            195: self.release_int_array_elements,
            196: self.release_long_array_elements,
            197: self.release_float_array_elements,
            198: self.release_double_array_elements,
            199: self.get_boolean_array_region,
            200: self.get_byte_array_region,
            201: self.get_char_array_region,
            202: self.get_short_array_region,
            203: self.get_int_array_region,
            204: self.get_long_array_region,
            205: self.get_float_array_region,
            206: self.get_double_array_region,
            207: self.set_boolean_array_region,
            208: self.set_byte_array_region,
            209: self.set_char_array_region,
            210: self.set_short_array_region,
            211: self.set_int_array_region,
            212: self.set_long_array_region,
            213: self.set_float_array_region,
            214: self.set_double_array_region,
            215: self.register_natives,
            216: self.unregister_natives,
            217: self.monitor_enter,
            218: self.monitor_exit,
            219: self.get_java_vm,
            220: self.get_string_region,
            221: self.get_string_utf_region,
            222: self.get_primitive_array_critical,
            223: self.release_primitive_array_critical,
            224: self.get_string_critical,
            225: self.release_string_critical,
            226: self.new_weak_global_ref,
            227: self.delete_weak_global_ref,
            228: self.exception_check,
            229: self.new_direct_byte_buffer,
            230: self.get_direct_buffer_address,
            231: self.get_direct_buffer_capacity,
            232: self.get_object_ref_type
        })

    def get_reference(self, idx):
        if idx == 0:
            return None

        if self._locals.in_range(idx):
            return self._locals.get(idx)

        if self._globals.in_range(idx):
            return self._globals.get(idx)

        raise RuntimeError('Invalid get_reference(%d)' % idx)

    def add_local_reference(self, obj):
        if not isinstance(obj, jobject):
            raise ValueError('Expected a jobject.')
        index = self._locals.add(obj)
        return index

    def set_local_reference(self, idx, newobj):
        if not isinstance(newobj, jobject):
            raise ValueError('Expected a jobject.')

        self._locals.set(idx, newobj)

    def get_local_reference(self, idx):
        r = self._locals.get(idx)
        return r

    def delete_local_reference(self, obj):
        if not isinstance(obj, jobject):
            raise ValueError('Expected a jobject.')

        self._locals.remove(obj)

    def clear_locals(self):
        self._locals.clear()

    def add_global_reference(self, obj):
        if not isinstance(obj, jobject):
            raise ValueError('Expected a jobject.')

        return self._globals.add(obj)

    def get_global_reference(self, idx):
        return self._globals.get(idx)
    #

    def delete_global_reference(self, obj):
        if not isinstance(obj, jobject):
            raise ValueError('Expected a jobject.')
        #
        return self._globals.remove(obj)
    #

    #args is a tuple or list
    def __read_args32(self, mu, args, args_type_list):
        #在这里处理八个字节参数问题，
        #1.第一个参数为jlong jdouble 直接跳过列表第一个成员，因为第一个成员刚好是call_xxx的第三个参数，根据调用约定，如果这个参数是8个字节，则直接跳过R3寄存器使用栈
        #2.jlong或者jdouble需要两个arg成一个参数，对应用层透明
        if args_type_list is None:
            return []
        #
        result = []
        args_index = 0
        n = len(args_type_list)
        nargs = len(args)
        args_list_index = 0
        while args_list_index < n:
            arg_name = args_type_list[args_list_index]
            if (args_index == 0 and arg_name in ("jlong", "jdouble")):
                #处理第一个参数(call_xxx第四个参数)跳过问题
                args_index =  args_index + 1
                continue
            #
            v = args[args_index]
            if arg_name in ('jint', "jchar", "jbyte", "jboolean"):
                result.append(v)
            #
            elif arg_name in ("jlong", "jdouble"):
                args_index = args_index + 1
                if (args_index >= nargs):
                    raise RuntimeError("read_args get long on args_type_list, but args len is not enough to read high bytes")
                #
                vh = args[args_index]
                value = (vh << 32) | v
                result.append(value)
            #
            elif arg_name == 'jstring' or arg_name == "jobject":
                ref = v
                jobj = self.get_reference(ref)
                obj = None
                if (jobj == None):
                    logging.warning("arg_name %s ref %d is not vaild maybe wrong arglist"%(arg_name, ref))
                    obj = JAVA_NULL
                else:
                    obj = jobj.value
                result.append(obj)
            else:
                raise NotImplementedError('Unknown arg name %s' % arg_name)
            args_index = args_index + 1
            args_list_index = args_list_index + 1
        #
        return result
    #

    def __read_args64(self, mu, args, args_type_list):
        #64w位情况简单得多，因为寄存器的大小为8字节，因此jlong，jdouble直接一个寄存器能装下，直接读即可
        if args_type_list is None:
            return []
        #
        result = []
        n = len(args_type_list)
        nargs = len(args)

        for args_index in nargs:
            arg_name = args_type_list[args_index]
            v = args[args_index]
            if arg_name in ('jint', "jchar", "jbyte", "jboolean", "jlong", "jdouble"):
                result.append(v)
            #
            elif arg_name == 'jstring' or arg_name == "jobject":
                ref = v
                jobj = self.get_reference(ref)
                obj = None
                if (jobj == None):
                    logging.warning("arg_name %s ref %d is not vaild maybe wrong arglist"%(arg_name, ref))
                    obj = JAVA_NULL
                else:
                    obj = jobj.value
                result.append(obj)
            else:
                raise NotImplementedError('Unknown arg name %s' % arg_name)
            #
        #
        return result
    #


    def __read_args_v32(self, mu, args_ptr, args_type_list):
        result = []
        if args_type_list is None:
            return result
        #
        for arg_name in args_type_list:
            #使用指针arg_ptr的作为call_xxx_v第四个参数,不会出现跳过第四个参数的情况,因为arg_ptr总是四个字节
            v = int.from_bytes(mu.mem_read(args_ptr, 4), byteorder='little')
            if arg_name in ('jint', "jchar", "jbyte", "jboolean"):
                result.append(v)
            elif arg_name in ("jlong", "jdouble"):
                args_ptr = args_ptr + 4
                vh = int.from_bytes(mu.mem_read(args_ptr, 4), byteorder='little')
                value = (vh << 32) | v
                result.append(value)
            #
            elif arg_name == 'jstring' or arg_name == "jobject":
                ref = v
                jobj = self.get_reference(ref)
                obj = None
                if (jobj == None):
                    logging.warning("arg_name %s ref %d is not vaild maybe wrong arglist"%(arg_name, ref))
                    obj = JAVA_NULL
                else:
                    obj = jobj.value
                result.append(obj)
            else:
                raise NotImplementedError('Unknown arg name %s' % arg_name)
            #
            args_ptr = args_ptr + 4
        #
        return result
    #

    def __read_args_v64(self, mu, args_ptr, args_type_list):
        result = []
        if args_type_list is None:
            return result
        #
        ptr_size = self._emu.get_ptr_size()            
        for arg_name in args_type_list:
            v = int.from_bytes(mu.mem_read(args_ptr, ptr_size), byteorder='little')
            if arg_name in ('jint', "jchar", "jbyte", "jboolean", "jlong", "jdouble"):
                result.append(v)
            
            elif arg_name == 'jstring' or arg_name == "jobject":
                ref = v
                jobj = self.get_reference(ref)
                obj = None
                if (jobj == None):
                    logging.warning("arg_name %s ref %d is not vaild maybe wrong arglist"%(arg_name, ref))
                    obj = JAVA_NULL
                else:
                    obj = jobj.value
                result.append(obj)
            else:
                raise NotImplementedError('Unknown arg name %s' % arg_name)
            #
            args_ptr = args_ptr + ptr_size
        #
        return result
    #

    #arg_type = 0 tuple or list, 1 arg_v, 2 array
    def __read_args_common(self, mu, args, args_type_list, arg_type):
        if (arg_type == 0):
            args_items = args
            return self.__read_args(mu, args_items, args_type_list)
        elif (arg_type == 1):
            args_ptr = args
            return self.__read_args_v(mu, args_ptr, args_type_list)
        else:
            raise RuntimeError("arg_type %d not support"%arg_type)
        #
    #

    @staticmethod
    def jobject_to_pyobject(obj):
        if(isinstance(obj, jobject)):
            return obj.value
        else:
            raise RuntimeError("jobject_to_pyobject unknown obj type %r"%obj)
        #
    #

    @native_method
    def get_version(self, mu, env):
        logger.debug("JNIEnv->GetVersion() was called")
        return 65542
    #

    @native_method
    def define_class(self, mu, env):
        raise NotImplementedError()

    @native_method
    def find_class(self, mu, env, name_ptr):
        """
        Returns a class object from a fully-qualified name, or NULL if the class cannot be found.
        """
        name = memory_helpers.read_utf8(mu, name_ptr)
        logger.debug("JNIEnv->FindClass(%s) was called" % name)

        pyclazz = self._class_loader.find_class_by_name(name)
        if pyclazz is None:
            # TODO: Proper Java error?
            raise RuntimeError('Could not find class \'%s\' for JNIEnv.' % name)

        if pyclazz.jvm_ignore:
            logger.debug("FindClass %s return 0 because of ignored")
            return 0
        #
        #jclass包裹的都是Class的对象(Java Class Object)
        jvm_clazz = pyclazz.class_object
        return self.add_local_reference(jclass(jvm_clazz))
    #

    @native_method
    def from_reflected_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def from_reflected_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def to_reflected_method(self, mu, env, class_idx, method_id, is_static):
        """
        Converts a method ID derived from cls to a java.lang.reflect.Method or java.lang.reflect.Constructor object.
        isStatic must be set to JNI_TRUE if the method ID refers to a static field, and JNI_FALSE otherwise.

        Throws OutOfMemoryError and returns 0 if fails.
        """
        clazz = self.get_reference(class_idx)

        if not isinstance(clazz, jclass):
            raise ValueError('Expected a jclass.')
        #
        class_obj = clazz.value

        pyclazz = class_obj.get_py_clazz()

        method = pyclazz.find_method_by_id(method_id)
        if method is None:
            raise RuntimeError("Could not find method ('%u') in class %s." % (method_id, pyclazz.jvm_name))

        if method.modifier & MODIFIER_STATIC:
            mu.mem_write(is_static, int(JNI_TRUE).to_bytes(4, byteorder='little'))
        else:
            mu.mem_write(is_static, int(JNI_FALSE).to_bytes(4, byteorder='little'))

        logger.debug("JNIEnv->ToReflectedMethod(%s, %s, %u) was called" % (pyclazz.jvm_name,
                                                                           method.name,
                                                                           is_static))

        if method.name == '<init>' and method.signature.endswith('V'):
            return Constructor(pyclazz, method)
        else:
            return Method(pyclazz, method)
        #
    #

    @native_method
    def get_superclass(self, mu, env, clazz_idx):
        jclazz = self.get_reference(clazz_idx)
        if not isinstance(jclazz, jclass):
            raise ValueError('Expected a jclass.')

        # Create class instance.
        class_obj = jclazz.value
        pyclass = class_obj.get_py_clazz()

        logger.debug("JNIEnv->GetSuperClass (%s) is called"%pyclass.jvm_name)

        pyclazz_super = pyclass.jvm_super
        if (not pyclazz_super):
            raise RuntimeError("super class for %s is None!!! you should at least inherit Object!!!")
        #
        logger.debug("JNIEnv->GetSuperClass (%s) return (%s)"%(pyclass.jvm_name, pyclazz_super.jvm_name))
        clazz_super_object = pyclazz_super.class_object
        return self.add_local_reference(jclass(clazz_super_object))

    @native_method
    def is_assignable_from(self, mu, env, clazz_idx1, clazz_idx2):
        jclazz1 = self.get_reference(clazz_idx1)
        jclazz2 = self.get_reference(clazz_idx2)
        # Create class instance.
        class_obj1 = jclazz1.value
        pyclass1 = class_obj1.get_py_clazz()

        class_obj2 = jclazz2.value
        pyclass2 = class_obj2.get_py_clazz()

        logger.debug("JNIEnv->IsAssignableFrom (%s,%s) is called"%(pyclass1.jvm_name, pyclass2.jvm_name))
        r = JNI_FALSE
        jvm_super = pyclass1.jvm_super
        while jvm_super != None:
            if (jvm_super == pyclass2):
                r = JNI_TRUE
                break
            #
            jvm_super = jvm_super.jvm_super
        #
        logger.debug("JNIEnv->IsAssignableFrom (%s,%s) return (%d)"%(pyclass1.jvm_name, pyclass2.jvm_name, r))
        return r
    #

    @native_method
    def to_reflected_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def throw(self, mu, env):
        raise RuntimeError("throw is call, maybe bug")
    #

    @native_method
    def throw_new(self, mu, env):
        raise RuntimeError("throw_new is call, maybe bug")
    #

    @native_method
    def exception_occurred(self, mu, env):
        logger.info("exception_occurred called skip")
        return 0
    #

    @native_method
    def exception_describe(self, mu, env):
        raise NotImplementedError()
    #

    @native_method
    def exception_clear(self, mu, env):
        """
        Clears any exception that is currently being thrown.
        If no exception is currently being thrown, this routine has no effect.
        """
        logger.debug("JNIEnv->ExceptionClear() was called")
        # TODO: Implement
        return None
    #

    @native_method
    def fatal_error(self, mu, env):
        raise NotImplementedError()

    @native_method
    def push_local_frame(self, mu, env):
        raise NotImplementedError()

    @native_method
    def pop_local_frame(self, mu, env):
        raise NotImplementedError()

    @native_method
    def new_global_ref(self, mu, env, jobj):
        """
        Creates a new global reference to the object referred to by the obj argument. The obj argument may be a
        global or local reference. Global references must be explicitly disposed of by calling DeleteGlobalRef().
        """
        logger.debug("JNIEnv->NewGlobalRef(%d) was called" % jobj)

        if jobj == 0:
            return 0

        obj = self.get_reference(jobj)

        if obj is None:
            # TODO: Implement global > global support (?)
            raise NotImplementedError('Invalid local reference obj.')
        #
        index = self.add_global_reference(obj)
        return index

    @native_method
    def delete_global_ref(self, mu, env, idx):
        """
        Deletes the global reference pointed to by globalRef.
        """
        logger.debug("JNIEnv->DeleteGlobalRef(%d) was called" % idx)

        if idx == 0:
            return None

        obj = self.get_global_reference(idx)
        self.delete_global_reference(obj)

    @native_method
    def delete_local_ref(self, mu, env, idx):
        """
        Deletes the local reference pointed to by localRef.
        """
        logger.debug("JNIEnv->DeleteLocalRef(%d) was called" % idx)

        if idx == 0:
            return None

        obj = self.get_local_reference(idx)
        self.delete_local_reference(obj)

    @native_method
    def is_same_object(self, mu, env, ref1, ref2):
        """
        Returns JNI_TRUE if ref1 and ref2 refer to the same Java object, or are both NULL; otherwise, returns JNI_FALSE.
        """
        logger.debug("JNIEnv->IsSameObject(%d, %d) was called" % (ref1, ref2))

        if ref1 == 0 and ref2 == 0:
            return JNI_TRUE

        obj1 = self.get_reference(ref1)
        obj2 = self.get_reference(ref2)
        pyobj1 = self.jobject_to_pyobject(obj1)
        pyobj2 = self.jobject_to_pyobject(obj2)
        
        if pyobj1 is pyobj2:
            return JNI_TRUE
        #

        return JNI_FALSE

    @native_method
    def new_local_ref(self, mu, env, ref):
        """
        Creates a new local reference that refers to the same object as ref.
        The given ref may be a global or local reference. Returns NULL if ref refers to null.
        """
        logger.debug("JNIEnv->NewLocalRef(%d) was called" % ref)

        obj = self.get_reference(ref)

        if obj is None:
            return 0

        return self.add_local_reference(obj)

    @native_method
    def ensure_local_capacity(self, mu, env):
        #raise NotImplementedError()
        #ignore
        return JNIEnv.JNI_OK
    #

    @native_method
    def alloc_object(self, mu, env):
        raise NotImplementedError()
    #

    def __new_object(self, mu, env, clazz_idx, method_id, args, args_type):
        # Get class reference.
        jclazz = self.get_reference(clazz_idx)
        if not isinstance(jclazz, jclass):
            raise ValueError('Expected a jclass.')

        # Create class instance.
        class_obj = jclazz.value
        
        pyclazz = class_obj.get_py_clazz()

        obj = pyclazz()

        # Get constructor method.
        method = pyclazz.find_method_by_id(method_id)
        if method.name != '<init>' or not method.signature.endswith('V'):
            raise ValueError('Class constructor has the wrong name or does not return void.')

        logger.debug("JNIEnv->NewObjectX(%s, %s, %r) was called" % (pyclazz.jvm_name, method.name, args))

        # Parse arguments.
        constructor_args = self.__read_args_common(mu, args, method.args_list, args_type)

        # Execute function.
        method.func(obj, self._emu, *constructor_args)

        return self.add_local_reference(jobject(obj))
    #

    #FIXME*args 无法确定参数个数，强行读取四个参数，未完善。
    @native_method
    def new_object(self, mu, env, clazz_idx, method_id, arg1, arg2, arg3, arg4):
        return self.__new_object(mu, env, clazz_idx, method_id, (arg1, arg2, arg3, arg4), 0)
    #

    @native_method
    def new_object_v(self, mu, env, clazz_idx, method_id, args_v):
        return self.__new_object(mu, env, clazz_idx, method_id, args_v, 1)
    #

    @native_method
    def new_object_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_object_class(self, mu, env, obj_idx):

        obj = self.get_reference(obj_idx)
        if (obj == None):
            # TODO: Proper Java error?
            raise RuntimeError('get_object_class can not get class for object id %d for JNIEnv.' %obj_idx)
        #
        pyobj = JNIEnv.jobject_to_pyobject(obj)
        logger.debug("JNIEnv->GetObjectClass(%r) was called" % (pyobj, ))

        pyclazz  = pyobj.__class__

        jvm_clazz = pyclazz.class_object
        return self.add_local_reference(jclass(jvm_clazz))
    #

    @native_method
    def is_instance_of(self, mu, env, obj_idx, class_idx):
        """
        Tests whether an object is an instance of a class.
        Returns JNI_TRUE if obj can be cast to clazz; otherwise, returns JNI_FALSE. A NULL object can be cast to any class.
        """
        obj = self.get_reference(obj_idx)
        if not isinstance(obj, jobject):
            raise ValueError('Expected a jobject.')

        clazz = self.get_reference(class_idx)
        if not isinstance(clazz, jclass):
            raise ValueError('Expected a jclass.')

        # TODO: Casting check (?)

        class_obj = clazz.value
        
        pyclazz = class_obj.get_py_clazz()

        pyobj = JNIEnv.jobject_to_pyobject(obj)
        return JNI_TRUE if pyobj.jvm_id == pyclazz.jvm_id else JNI_FALSE
    #

    @native_method
    def get_method_id(self, mu, env, clazz_idx, name_ptr, sig_ptr):
        """
        Returns the method ID for an instance (nonstatic) method of a class or interface. The method may be defined
        in one of the clazz’s superclasses and inherited by clazz. The method is determined by its name and signature.
        """
        name = memory_helpers.read_utf8(mu, name_ptr)
        sig = memory_helpers.read_utf8(mu, sig_ptr)
        clazz = self.get_reference(clazz_idx)
        logger.debug("JNIEnv->GetMethodId(%d, %s, %s) was called" % (clazz_idx, name, sig))

        if not isinstance(clazz, jclass):
            raise ValueError('Expected a jclass.')
        #

        class_obj = clazz.value
        
        pyclazz = class_obj.get_py_clazz()

        logging.debug("get_method_id type %s"%(pyclazz))
        method = pyclazz.find_method(name, sig)

        if method is None:
            # TODO: Proper Java error?
            raise RuntimeError("Could not find method ('%s', '%s') in class %s." % (name, sig, pyclazz.jvm_name))
        logger.debug("JNIEnv->GetMethodId(%d, %s, %s) return 0x%08X"%(clazz_idx, name, sig, method.jvm_id))
        return method.jvm_id
    #

    def __call_xxx_method(self, mu, env, obj_idx, method_id, args, args_type, is_wide=False):
        obj = self.get_reference(obj_idx)

        if not isinstance(obj, jobject):
            raise ValueError('Expected a jobject.')
        pyobj = JNIEnv.jobject_to_pyobject(obj)

        method = pyobj.__class__.find_method_by_id(method_id)
        if method is None:
            # TODO: Proper Java error?
            raise RuntimeError("Could not find method %d in object %s by id." % (method_id, pyobj.jvm_name))
        #

        logger.debug("JNIEnv->CallXXXMethodX(%s, %s <%s>, %r) was called" % (
            pyobj.jvm_name,
            method.name,
            method.signature, args))

        # Parse arguments.
        constructor_args = self.__read_args_common(mu, args, method.args_list, args_type)

        sig = method.signature
        name = method.name
        #因为要支持多态,通过method_id找到的方法可能是基类的方法,不可以直接调用,需要获取签名和名字,通过子类的find_method才可以找到真正的实现方法.

        real_method = pyobj.__class__.find_method(name, sig)
        v = real_method.func(pyobj, self._emu, *constructor_args)

        if (not is_wide):
            return v
        else:
            rhigh = v >> 32
            rlow = v & 0x0FFFFFFFF
            return (rlow, rhigh)
        #
    #

    @native_method
    def call_object_method(self, mu, env, obj_idx, method_id, arg1, arg2, arg3, arg4):
        return self.__call_xxx_method(mu, env, obj_idx, method_id, (arg1, arg2, arg3, arg4), 0)
    #

    @native_method
    def call_object_method_v(self, mu, env, obj_idx, method_id, args):
        return self.__call_xxx_method(mu, env, obj_idx, method_id, args, 1)
    #

    @native_method
    def call_object_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_boolean_method(self, mu, env, obj_idx, method_id, arg1, arg2, arg3, arg4):
        return self.__call_xxx_method(mu, env, obj_idx, method_id, (arg1, arg2, arg3, arg4), 0)
    #

    @native_method
    def call_boolean_method_v(self, mu, env, obj_idx, method_id, args):
        return self.__call_xxx_method(mu, env, obj_idx, method_id, args, 1)
    #

    @native_method
    def call_boolean_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_byte_method(self, mu, env, obj_idx, method_id, arg1, arg2, arg3, arg4):
        return self.__call_xxx_method(mu, env, obj_idx, method_id, (arg1, arg2, arg3, arg4), 0)
    #

    @native_method
    def call_byte_method_v(self, mu, env, obj_idx, method_id, args):
        return self.__call_xxx_method(mu, env, obj_idx, method_id, args, 1)
    #

    @native_method
    def call_byte_method_a(self, mu, env):
        raise NotImplementedError()


    @native_method
    def call_char_method(self, mu, env, obj_idx, method_id, arg1, arg2, arg3, arg4):
        return self.__call_xxx_method(mu, env, obj_idx, method_id, (arg1, arg2, arg3, arg4), 0)
    #

    @native_method
    def call_char_method_v(self, mu, env, obj_idx, method_id, args):
        return self.__call_xxx_method(mu, env, obj_idx, method_id, args, 1)
    #

    @native_method
    def call_char_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_short_method(self, mu, env, obj_idx, method_id, arg1, arg2, arg3, arg4):
        return self.__call_xxx_method(mu, env, obj_idx, method_id, (arg1, arg2, arg3, arg4), 0)
    #

    @native_method
    def call_short_method_v(self, mu, env, obj_idx, method_id, args):
        return self.__call_xxx_method(mu, env, obj_idx, method_id, args, 1)
    #

    @native_method
    def call_short_method_a(self, mu, env):
        raise NotImplementedError()

    #上层不知道个数，暂时读四个寄存器，不会错
    @native_method
    def call_int_method(self, mu, env, obj_idx, method_id, arg1, arg2, arg3, arg4):
        return self.__call_xxx_method(mu, env, obj_idx, method_id, (arg1, arg2, arg3, arg4), 0)
    #

    @native_method
    def call_int_method_v(self, mu, env, obj_idx, method_id, args):
        return self.__call_xxx_method(mu, env, obj_idx, method_id, args, 1)
    #

    @native_method
    def call_int_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_long_method(self, mu, env, obj_idx, method_id, arg1, arg2, arg3, arg4):
        return self.__call_xxx_method(mu, env, obj_idx, method_id, (arg1, arg2, arg3, arg4), 0, True)
    #

    @native_method
    def call_long_method_v(self, mu, env, obj_idx, method_id, args):
        return self.__call_xxx_method(mu, env, obj_idx, method_id, args, 1, True)
    #

    @native_method
    def call_long_method_a(self, mu, env):
        raise NotImplementedError()
    #
    
    @native_method
    def call_float_method(self, mu, env, obj_idx, method_id, arg1, arg2, arg3, arg4):
        return self.__call_xxx_method(mu, env, obj_idx, method_id, (arg1, arg2, arg3, arg4), 0)
    #

    @native_method
    def call_float_method_v(self, mu, env, obj_idx, method_id, args):
        return self.__call_xxx_method(mu, env, obj_idx, method_id, args, 1)
    #

    @native_method
    def call_float_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_double_method(self, mu, env, obj_idx, method_id, arg1, arg2, arg3, arg4):
        raise NotImplementedError()
        #return self.__call_xxx_method(mu, env, obj_idx, method_id, (arg1, arg2, arg3, arg4), 0)
    #

    @native_method
    def call_double_method_v(self, mu, env, obj_idx, method_id, args):
        raise NotImplementedError()
        #return self.__call_xxx_method(mu, env, obj_idx, method_id, args, 1)
    #

    @native_method
    def call_double_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_void_method(self, mu, env, obj_idx, method_id, arg1, arg2, arg3, arg4):
        self.__call_xxx_method(mu, env, obj_idx, method_id, (arg1, arg2, arg3, arg4), 0)
    #

    @native_method
    def call_void_method_a(self, mu, env):
        raise NotImplementedError()
    #

    @native_method
    def call_void_method_v(self, mu, env, obj_idx, method_id, args):
        self.__call_xxx_method(mu, env, obj_idx, method_id, args, 1)
    #

    @native_method
    def call_nonvirtual_object_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_object_method_v(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_object_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_boolean_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_boolean_method_v(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_boolean_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_byte_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_byte_method_v(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_byte_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_char_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_char_method_v(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_char_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_short_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_short_method_v(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_short_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_int_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_int_method_v(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_int_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_long_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_long_method_v(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_long_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_float_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_float_method_v(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_float_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_double_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_double_method_v(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_double_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_void_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_void_method_v(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_void_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_field_id(self, mu, env, clazz_idx, name_ptr, sig_ptr):
        """
        Returns the field ID for an instance (nonstatic) field of a class. The field is specified by its name and
        signature. The Get<type>Field and Set<type>Field families of accessor functions use field IDs to retrieve
        object fields.
        """
        name = memory_helpers.read_utf8(mu, name_ptr)
        sig = memory_helpers.read_utf8(mu, sig_ptr)
        clazz = self.get_reference(clazz_idx)

        logger.debug("JNIEnv->GetFieldId(%d, %s, %s) was called" % (clazz_idx, name, sig))

        class_obj = clazz.value
        
        pyclazz = class_obj.get_py_clazz()

        field = pyclazz.find_field(name, sig, False)

        if field is None:
            # TODO: Proper Java error?
            raise RuntimeError("Could not find field ('%s', '%s') in class %s." % (name, sig, pyclazz.jvm_name))

        if field.ignore:
            return 0

        return field.jvm_id

    def __get_xxx_field(self, mu, env, obj_idx, field_id, is_wide = False):
        obj = self.get_reference(obj_idx)

        if not isinstance(obj, jobject):
            raise ValueError('Expected a jobject.')

        pyobj = JNIEnv.jobject_to_pyobject(obj)
        field = pyobj.__class__.find_field_by_id(field_id)

        if field is None:
            # TODO: Proper Java error?
            raise RuntimeError("Could not find field %d in object %s by id." % (field_id, pyobj.jvm_name))

        logger.debug("JNIEnv->GetXXXField(%s, %s <%s>) was called" % (pyobj.jvm_name,
                                                                         field.name,
                                                                         field.signature))
        v = getattr(pyobj, field.name)
        if (not is_wide):
            return v
        else:
            rhigh = v >> 32
            rlow = v & 0x0FFFFFFFF
            return (rlow, rhigh)
        #
    #
    @native_method
    def get_object_field(self, mu, env, obj_idx, field_id):
        return self.__get_xxx_field(mu, env, obj_idx, field_id)
    #

    @native_method
    def get_boolean_field(self, mu, env, obj_idx, field_id):
        return self.__get_xxx_field(mu, env, obj_idx, field_id)
    #

    @native_method
    def get_byte_field(self, mu, env, obj_idx, field_id):
        return self.__get_xxx_field(mu, env, obj_idx, field_id)
    #

    @native_method
    def get_char_field(self, mu, env, obj_idx, field_id):
        return self.__get_xxx_field(mu, env, obj_idx, field_id)
    #

    @native_method
    def get_short_field(self, mu, env, obj_idx, field_id):
        return self.__get_xxx_field(mu, env, obj_idx, field_id)
    #

    @native_method
    def get_int_field(self, mu, env, obj_idx, field_id):
        return self.__get_xxx_field(mu, env, obj_idx, field_id)
    #

    @native_method
    def get_long_field(self, mu, env, obj_idx, field_id):
        return self.__get_xxx_field(mu, env, obj_idx, field_id, True)
    #

    @native_method
    def get_float_field(self, mu, env, obj_idx, field_id):
        return self.__get_xxx_field(mu, env, obj_idx, field_id)
    #

    @native_method
    def get_double_field(self, mu, env, obj_idx, field_id):
        raise NotImplementedError()
    #

    def __set_xxx_field(self, mu, env, obj_idx, field_id, value, is_obj_value = False):
        obj = self.get_reference(obj_idx)

        if not isinstance(obj, jobject):
            raise ValueError('Expected a jobject.')

        pyobj = JNIEnv.jobject_to_pyobject(obj)
        field = pyobj.__class__.find_field_by_id(field_id)

        if field is None:
            # TODO: Proper Java error?
            raise RuntimeError("Could not find field %d in object %s by id." % (field_id, pyobj.jvm_name))
        #
        logger.debug("JNIEnv->SetXXXField(%s, %s <%s>, %r) was called" % (pyobj.jvm_name,
                                                                         field.name,
                                                                         field.signature, 
                                                                         value))

        v = None
        if (is_obj_value):
            value_idx = value
            value_obj = self.get_reference(value_idx)
            v = JNIEnv.jobject_to_pyobject(value_obj)
        #
        else:
            v = value
        #
        setattr(pyobj, field.name, v)
    #

    @native_method
    def set_object_field(self, mu, env, obj_idx, field_id, value):
        self.__set_xxx_field(mu, env, obj_idx, field_id, value, True)
    #

    @native_method
    def set_boolean_field(self, mu, env, obj_idx, field_id, value):
        self.__set_xxx_field(mu, env, obj_idx, field_id, value)
    #

    @native_method
    def set_byte_field(self, mu, env, obj_idx, field_id, value):
        self.__set_xxx_field(mu, env, obj_idx, field_id, value)
    #

    @native_method
    def set_char_field(self, mu, env, obj_idx, field_id, value):
        self.__set_xxx_field(mu, env, obj_idx, field_id, value)
    #

    @native_method
    def set_short_field(self, mu, env, obj_idx, field_id, value):
        self.__set_xxx_field(mu, env, obj_idx, field_id, value)
    #

    @native_method
    def set_int_field(self, mu, env, obj_idx, field_id, value):
        self.__set_xxx_field(mu, env, obj_idx, field_id, value)
    #

    @native_method
    def set_long_field(self, mu, env, obj_idx, field_id, value):
        self.__set_xxx_field(mu, env, obj_idx, field_id, value)
    #

    @native_method
    def set_float_field(self, mu, env, obj_idx, field_id, value):
        self.__set_xxx_field(mu, env, obj_idx, field_id, value)
    #

    @native_method
    def set_double_field(self, mu, env, obj_idx, field_id, value):
        self.__set_xxx_field(mu, env, obj_idx, field_id, value)
    #

    @native_method
    def get_static_method_id(self, mu, env, clazz_idx, name_ptr, sig_ptr):
        """
        Returns the method ID for a static method of a class. The method is specified by its name and signature.
        """
        name = memory_helpers.read_utf8(mu, name_ptr)
        sig = memory_helpers.read_utf8(mu, sig_ptr)
        clazz = self.get_reference(clazz_idx)

        logger.debug("JNIEnv->GetStaticMethodId(%d, %s, %s) was called" % (clazz_idx, name, sig))

        if not isinstance(clazz, jclass):
            raise ValueError('Expected a jclass.')
        #

        class_obj = clazz.value
        
        pyclazz = class_obj.get_py_clazz()
        method = pyclazz.find_method(name, sig)

        if method is None:
            # TODO: Proper Java error?
            raise RuntimeError(
                "Could not find static method ('%s', '%s') in class %s." % (name, sig, pyclazz.jvm_name))

        if method.ignore:
            return 0
        logger.debug("JNIEnv->GetStaticMethodId(%d, %s, %s) return 0x%08X" % (clazz_idx, name, sig, method.jvm_id))

        return method.jvm_id


    def __call_static_xxx_method(self, mu, env, clazz_idx, method_id, args, args_type, is_wide = False):
        clazz = self.get_reference(clazz_idx)

        if not isinstance(clazz, jclass):
            raise ValueError('Expected a jclass.')

        class_obj = clazz.value
        
        pyclazz = class_obj.get_py_clazz()

        method = pyclazz.find_method_by_id(method_id)

        if method is None:
            # TODO: Proper Java error?
            raise RuntimeError("Could not find method %d in class %s by id." % (method_id, pyclazz.jvm_name))

        logger.debug("JNIEnv->CallStaticXXXMethodX(%s, %s <%s>, %r) was called" % (
            pyclazz.jvm_name,
            method.name,
            method.signature, args))

        # Parse arguments.
        constructor_args = self.__read_args_common(mu, args, method.args_list, args_type)

        v = method.func(self._emu, *constructor_args)
        #FIXME python的double怎么办？？？
        if (not is_wide):
            return v
        else:
            rhigh = v >> 32
            rlow = v & 0x0FFFFFFFF
            return (rlow, rhigh)
        #
    #

    @native_method
    def call_static_object_method(self, mu, env, clazz_idx, method_id, arg1, arg2, arg3, arg4):
        return self.__call_static_xxx_method(mu, env, clazz_idx, method_id, (arg1, arg2, arg3, arg4), 0)
    #

    @native_method
    def call_static_object_method_v(self, mu, env, clazz_idx, method_id, args):
        return self.__call_static_xxx_method(mu, env, clazz_idx, method_id, args, 1)
    #

    @native_method
    def call_static_object_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_static_boolean_method(self, mu, env, clazz_idx, method_id, arg1, arg2, arg3, arg4):
        return self.__call_static_xxx_method(mu, env, clazz_idx, method_id, (arg1, arg2, arg3, arg4), 0)
    #

    @native_method
    def call_static_boolean_method_v(self, mu, env, clazz_idx, method_id, args):
        return self.__call_static_xxx_method(mu, env, clazz_idx, method_id, args, 1)
    #

    @native_method
    def call_static_boolean_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_static_byte_method(self, mu, env, clazz_idx, method_id, arg1, arg2, arg3, arg4):
        return self.__call_static_xxx_method(mu, env, clazz_idx, method_id, (arg1, arg2, arg3, arg4), 0)
    #

    @native_method
    def call_static_byte_method_v(self, mu, env, clazz_idx, method_id, args):
        return self.__call_static_xxx_method(mu, env, clazz_idx, method_id, args, 1)
    #

    @native_method
    def call_static_byte_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_static_char_method(self, mu, env, clazz_idx, method_id, arg1, arg2, arg3, arg4):
        return self.__call_static_xxx_method(mu, env, clazz_idx, method_id, (arg1, arg2, arg3, arg4), 0)
    #

    @native_method
    def call_static_char_method_v(self, mu, env, clazz_idx, method_id, args):
        return self.__call_static_xxx_method(mu, env, clazz_idx, method_id, args, 1)
    #

    @native_method
    def call_static_char_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_static_short_method(self, mu, env, clazz_idx, method_id, arg1, arg2, arg3, arg4):
        return self.__call_static_xxx_method(mu, env, clazz_idx, method_id, (arg1, arg2, arg3, arg4), 0)
    #
        
    @native_method
    def call_static_short_method_v(self, mu, env, clazz_idx, method_id, args):
        return self.__call_static_xxx_method(mu, env, clazz_idx, method_id, args, 1)
    #

    @native_method
    def call_static_short_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_static_int_method(self, mu, env, clazz_idx, method_id, arg1, arg2, arg3, arg4):
        return self.__call_static_xxx_method(mu, env, clazz_idx, method_id, (arg1, arg2, arg3, arg4), 0)
    #

    @native_method
    def call_static_int_method_v(self, mu, env, clazz_idx, method_id, args):
        return self.__call_static_xxx_method(mu, env, clazz_idx, method_id, args, 1)
    #

    @native_method
    def call_static_int_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_static_long_method(self, mu, env, clazz_idx, method_id, arg1, arg2, arg3, arg4):
        #raise NotImplementedError()
        return self.__call_static_xxx_method(mu, env, clazz_idx, method_id, (arg1, arg2, arg3, arg4), 0, True)
    #

    @native_method
    def call_static_long_method_v(self, mu, env, clazz_idx, method_id, args):
        #raise NotImplementedError()
        return self.__call_static_xxx_method(mu, env, clazz_idx, method_id, args, 1, True)
    #

    @native_method
    def call_static_long_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_static_float_method(self, mu, env, clazz_idx, method_id, arg1, arg2, arg3, arg4):
        return self.__call_static_xxx_method(mu, env, clazz_idx, method_id, (arg1, arg2, arg3, arg4), 0)
    #

    @native_method
    def call_static_float_method_v(self, mu, env, clazz_idx, method_id, args):
        return self.__call_static_xxx_method(mu, env, clazz_idx, method_id, args, 1)
    #

    @native_method
    def call_static_float_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_static_double_method(self, mu, env, clazz_idx, method_id, arg1, arg2, arg3, arg4):
        raise NotImplementedError()
        #return self.__call_static_xxx_method(mu, env, clazz_idx, method_id, (arg1, arg2, arg3, arg4), 0)
    #

    @native_method
    def call_static_double_method_v(self, mu, env, clazz_idx, method_id, args):
        raise NotImplementedError()
        #return self.__call_static_xxx_method(mu, env, clazz_idx, method_id, args, 1)
    #

    @native_method
    def call_static_double_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_static_void_method(self, mu, env, clazz_idx, method_id, arg1, arg2, arg3, arg4):
        self.__call_static_xxx_method(mu, env, clazz_idx, method_id, (arg1, arg2, arg3, arg4), 0)
    #

    @native_method
    def call_static_void_method_v(self, mu, env, clazz_idx, method_id, args):
        self.__call_static_xxx_method(mu, env, clazz_idx, method_id, args, 1)
    #

    @native_method
    def call_static_void_method_a(self, mu, env):
        raise NotImplementedError()
    #


    @native_method
    def get_static_field_id(self, mu, env, clazz_idx, name_ptr, sig_ptr):
        """
        Returns the field ID for a static field of a class. The field is specified by its name and signature. The
        GetStatic<type>Field and SetStatic<type>Field families of accessor functions use field IDs to retrieve static
        fields.
        """
        name = memory_helpers.read_utf8(mu, name_ptr)
        sig = memory_helpers.read_utf8(mu, sig_ptr)

        logger.debug("JNIEnv->GetStaticFieldId(%d, %s, %s) was called" % (clazz_idx, name, sig))

        clazz = self.get_reference(clazz_idx)

        class_obj = clazz.value
        
        pyclazz = class_obj.get_py_clazz()

        field = pyclazz.find_field(name, sig, True)

        if field is None:
            # TODO: Proper Java error?
            raise RuntimeError(
                "Could not find static field ('%s', '%s') in class %s." % (name, sig, pyclazz.jvm_name))

        if field.ignore:
            return 0

        return field.jvm_id
    #

    def __get_static_xxx_field(self, mu, env, clazz_idx, field_id, is_wide = False):

        logger.debug("JNIEnv->GetStaticXXXField(%d, %d) was called" % (clazz_idx, field_id))

        clazz = self.get_reference(clazz_idx)

        class_obj = clazz.value
        
        pyclazz = class_obj.get_py_clazz()

        field = pyclazz.find_field_by_id(field_id)

        r = field.static_value
        logger.debug("JNIEnv->GetStaticXXXField return %r"%r)
        v = field.static_value
        if (not is_wide):
            return v
        else:
            rhigh = v >> 32
            rlow = v & 0x0FFFFFFFF
            return (rlow, rhigh)
        #
    #

    @native_method
    def get_static_object_field(self, mu, env, clazz_idx, field_id):
        return self.__get_static_xxx_field(mu, env, clazz_idx, field_id)
    #

    @native_method
    def get_static_boolean_field(self, mu, env, clazz_idx, field_id):
        return self.__get_static_xxx_field(mu, env, clazz_idx, field_id)
    #

    @native_method
    def get_static_byte_field(self, mu, env, clazz_idx, field_id):
        return self.__get_static_xxx_field(mu, env, clazz_idx, field_id)
    #

    @native_method
    def get_static_char_field(self, mu, env, clazz_idx, field_id):
        return self.__get_static_xxx_field(mu, env, clazz_idx, field_id)
    #

    @native_method
    def get_static_short_field(self, mu, env, clazz_idx, field_id):
        return self.__get_static_xxx_field(mu, env, clazz_idx, field_id)
    #

    @native_method
    def get_static_int_field(self, mu, env, clazz_idx, field_id):
        return self.__get_static_xxx_field(mu, env, clazz_idx, field_id)
    #

    @native_method
    def get_static_long_field(self, mu, env, clazz_idx, field_id):
        return self.__get_static_xxx_field(mu, env, clazz_idx, field_id, True)
    #

    @native_method
    def get_static_float_field(self, mu, env):
        return self.__get_static_xxx_field(mu, env, clazz_idx, field_id)
    #

    @native_method
    def get_static_double_field(self, mu, env):
        return self.__get_static_xxx_field(mu, env, clazz_idx, field_id, True)
    #

    @native_method
    def set_static_object_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_static_boolean_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_static_byte_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_static_char_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_static_short_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_static_int_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_static_long_field(self, mu, env, clazz_idx, field_id, _, value_l, value_h):
        #注意，由于刚好第四个参数是8个字节，arm32不会使用R3作为寄存器传递参数了，而是跳过R3直接使用栈，
        value = value_h << 32 | value_l
        logger.info("JNIEnv->set_static_long_field (%u, %u, 0x%016X)"%(clazz_idx, field_id, value))
        clazz = self.get_reference(clazz_idx)

        if not isinstance(clazz, jclass):
            raise ValueError('Expected a jclass.')

        class_obj = clazz.value
        
        pyclazz = class_obj.get_py_clazz()

        field = pyclazz.find_field_by_id(field_id)
        #FIXME: 对field支持还不完善，非stativ value无法设置，需要改进
        field.static_value = value
    #

    @native_method
    def set_static_float_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_static_double_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def new_string(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_string_length(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_string_chars(self, mu, env):
        raise NotImplementedError()

    @native_method
    def release_string_chars(self, mu, env):
        raise NotImplementedError()

    @native_method
    def new_string_utf(self, mu, env, utf8_ptr):
        pystr = memory_helpers.read_utf8(mu, utf8_ptr)
        logger.debug("JNIEnv->NewStringUtf(%s) was called" % pystr)
        string =String(pystr)
        idx = self.add_local_reference(jobject(string))
        logger.debug("JNIEnv->NewStringUtf(%s) return id(%d)" %(pystr, idx))
        return idx

    @native_method
    def get_string_utf_length(self, mu, env, string):
        
        str_ref = self.get_reference(string)
        str_obj = str_ref.value
        if (str_obj == JAVA_NULL):
            return 0
        #
        str_val = str_obj.get_py_string()
        return len(str_val)
    #

    @native_method
    def get_string_utf_chars(self, mu, env, string, is_copy_ptr):
        logger.debug("JNIEnv->GetStringUtfChars(%u, %x) was called" % (string, is_copy_ptr))


        str_ref = self.get_reference(string)
        str_obj = str_ref.value
        if (str_obj == JAVA_NULL):
            return JAVA_NULL
        #
        str_val = str_obj.get_py_string()
        #FIXME use malloc
        str_ptr = self._emu.memory.map(0, len(str_val)+1, UC_PROT_READ | UC_PROT_WRITE)

        logger.debug("=> %s" % str_val)
        if is_copy_ptr != 0:
            #TODO 观察行为,真机总是返回true,但是根据文档,返回false应该也没问题
            #https://stackoverflow.com/questions/30992989/is-iscopy-field-always-necessary-in-android
            mu.mem_write(is_copy_ptr, int(0).to_bytes(1, byteorder='little'))
        #
        memory_helpers.write_utf8(mu, str_ptr, str_val)

        return str_ptr
    #

    @native_method
    def release_string_utf_chars(self, mu, env, string, utf8_ptr):
        
        pystr = memory_helpers.read_utf8(mu, utf8_ptr)
        logger.debug("JNIEnv->ReleaseStringUtfChars(%u, %s) was called" % (string, pystr))
        if (utf8_ptr != 0):
            self._emu.memory.unmap(utf8_ptr, len(pystr)+1)
        #
    #

    @native_method
    def get_array_length(self, mu, env, array):
        logger.debug("JNIEnv->GetArrayLength(%u) was called" % array)

        obj = self.get_reference(array)

        pyobj = JNIEnv.jobject_to_pyobject(obj)
        return len(pyobj)
    #

    @native_method
    def new_object_array(self, mu, env, size, class_idx, obj_init):
        logger.debug("JNIEnv->NewObjectArray(%d, %u, %r) was called" %(size, class_idx, obj_init))
        clazz = self.get_reference(class_idx)

        if not isinstance(clazz, jclass):
            raise ValueError('Expected a jclass.')
        #

        class_obj = clazz.value
        
        pyclazz = class_obj.get_py_clazz()
        
        arr_item_cls_name = pyclazz.jvm_name

        pyarr = []
        for i in range(0, size):
            pyarr.append(JAVA_NULL)
        #
        
        if (obj_init != JAVA_NULL):
            obj = self.get_reference(obj_init)
            pyobj = self.jobject_to_pyobject(obj)
            pyarr[0] = pyobj
        #
        new_jvm_name = ""
        #FIXME check if is array
        if (arr_item_cls_name[0] == "["):
            new_jvm_name = "[%s"%arr_item_cls_name
        #
        else: 
            new_jvm_name = "[L%s;"%arr_item_cls_name
        #
        pyarray_clazz = self._class_loader.find_class_by_name(new_jvm_name)
        if (pyarray_clazz == None):
            #jvm_name=None, jvm_fields=None, jvm_ignore=False, jvm_super=None
            #动态创建Array新类，因为Descriptor会变
            #pyarray_clazz = JavaClassDef("%s_Array"%arr_item_cls_name, (Array,), {}, jvm_name=new_jvm_name, jvm_super=Array)
            #self._class_loader.add_class(pyarray_clazz)
            raise RuntimeError("NewObjectArray Array Class %s not found"%new_jvm_name)
        #
        arr = pyarray_clazz(pyarr)
        return self.add_local_reference(jobject(arr))
        
    #

    @native_method
    def get_object_array_element(self, mu, env, array_idx, item_idx):
        logger.debug("JNIEnv->GetObjectArrayElement(%u, %u) was called" % (array_idx, item_idx))

        array_obj = self.get_reference(array_idx)

        array_pyobj = JNIEnv.jobject_to_pyobject(array_obj)
        pyobj_item = array_pyobj[item_idx]
        if (pyobj_item == JAVA_NULL):
            return JAVA_NULL
        return self.add_local_reference(jobject(pyobj_item))
    #

    @native_method
    def set_object_array_element(self, mu, env, array_idx, index, obj_idx):
        logger.debug("JNIEnv->SetObjectArrayElement(%u, %u, %u) was called" % (array_idx, index, obj_idx))
        array_obj = self.get_reference(array_idx)

        array_pyobj = JNIEnv.jobject_to_pyobject(array_obj)
        obj = self.get_reference(obj_idx)
        pyobj = JNIEnv.jobject_to_pyobject(obj)
        array_pyobj[index] = pyobj
    #

    @native_method
    def new_boolean_array(self, mu, env):
        raise NotImplementedError()

    @native_method
    def new_byte_array(self, mu, env, bytelen):
        logger.debug("JNIEnv->NewByteArray(%u) was called" % bytelen)
        barr = bytearray([0] * bytelen)
        arr = Array(barr)
        return self.add_local_reference(jobject(arr))
    #

    @native_method
    def new_char_array(self, mu, env):
        raise NotImplementedError()

    @native_method
    def new_short_array(self, mu, env):
        raise NotImplementedError()

    @native_method
    def new_int_array(self, mu, env):
        raise NotImplementedError()

    @native_method
    def new_long_array(self, mu, env):
        raise NotImplementedError()

    @native_method
    def new_float_array(self, mu, env):
        raise NotImplementedError()

    @native_method
    def new_double_array(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_boolean_array_elements(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_byte_array_elements(self, mu, env, array_idx, is_copy_ptr):
        logger.debug("JNIEnv->get_byte_array_elements(%u, %u) was called" % (array_idx, is_copy_ptr))

        if is_copy_ptr != 0:
            raise NotImplementedError()
        #

        obj = self.get_reference(array_idx)
        pyobj = JNIEnv.jobject_to_pyobject(obj)
        items = pyobj.get_py_items()
        items_len = len(items)
        extra_n = 4
        #FIXME use malloc
        buf = self._emu.memory.map(0, extra_n+items_len, UC_PROT_READ | UC_PROT_WRITE)

        logger.debug("=> %r" % items)

        #协议约定前四个字节必定是长度
        mu.mem_write(buf, items_len.to_bytes(extra_n, 'little'))
        b = bytes(items)
        mu.mem_write(buf+extra_n, b)
        return buf+extra_n
    #


    @native_method
    def get_char_array_elements(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_short_array_elements(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_int_array_elements(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_long_array_elements(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_float_array_elements(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_double_array_elements(self, mu, env):
        raise NotImplementedError()

    @native_method
    def release_boolean_array_elements(self, mu, env):
        raise NotImplementedError()

    @native_method
    def release_byte_array_elements(self, mu, env,array_idx, elems, mode):
        if (elems == JAVA_NULL):
            return
        #
        #前四个字节必为长度
        logger.debug("JNIEnv->ReleaseByteArrayElements(%u, %u, %u) was called" % (array_idx, elems, mode))
        true_buf = elems - 4
        b = mu.mem_read(true_buf, 4)
        elems_sz =  int.from_bytes(b, byteorder='little', signed = False)
        self._emu.memory.unmap(true_buf, elems_sz+4)
    #

    @native_method
    def release_char_array_elements(self, mu, env):
        raise NotImplementedError()

    @native_method
    def release_short_array_elements(self, mu, env):
        raise NotImplementedError()

    @native_method
    def release_int_array_elements(self, mu, env):
        raise NotImplementedError()

    @native_method
    def release_long_array_elements(self, mu, env):
        raise NotImplementedError()

    @native_method
    def release_float_array_elements(self, mu, env):
        raise NotImplementedError()

    @native_method
    def release_double_array_elements(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_boolean_array_region(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_byte_array_region(self, mu, env, array_idx, start, len_in, buf_ptr):
        logger.debug("JNIEnv->GetByteArrayRegion(%u, %u, %u, 0x%x) was called" % (array_idx, start, len_in, buf_ptr))

        obj = self.get_reference(array_idx)
        '''
        if not isinstance(obj, jbyteArray):
            raise ValueError('Expected a jbyteArray.')
        '''
        pyobj = JNIEnv.jobject_to_pyobject(obj)
        barr = pyobj.get_py_items()
        mu.mem_write(buf_ptr, bytes(barr[start:start + len_in]))

        return None
    #

    @native_method
    def get_char_array_region(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_short_array_region(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_int_array_region(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_long_array_region(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_float_array_region(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_double_array_region(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_boolean_array_region(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_byte_array_region(self, mu, env, arrayJREF, startIndex, length, bufAddress):
        string = memory_helpers.read_byte_array(mu, bufAddress, length)
        logger.debug("JNIEnv->SetByteArrayRegion was called")
        arr = Array(string)
        self.set_local_reference(arrayJREF, jobject(arr))
    #

    @native_method
    def set_char_array_region(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_short_array_region(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_int_array_region(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_long_array_region(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_float_array_region(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_double_array_region(self, mu, env):
        raise NotImplementedError()

    @native_method
    def register_natives(self, mu, env, clazz_id, methods, methods_count):
        logger.debug("JNIEnv->RegisterNatives(%d, 0x%08X, %d) was called" % (clazz_id, methods, methods_count))

        clazz = self.get_reference(clazz_id)

        if not isinstance(clazz, jclass):
            raise ValueError('Expected a jclass but type %r value %r getted.'%(type(clazz), clazz))

        class_obj = clazz.value
        
        pyclazz = class_obj.get_py_clazz()
        ptr_sz = self._emu.get_ptr_size()

        for i in range(0, methods_count):
            ptr_name = memory_helpers.read_ptr_sz(mu, (i * 3*ptr_sz) + methods, ptr_sz)
            ptr_sign = memory_helpers.read_ptr_sz(mu, (i * 3*ptr_sz) + methods + ptr_sz, ptr_sz)
            ptr_func = memory_helpers.read_ptr_sz(mu, (i * 3*ptr_sz) + methods + 2*ptr_sz, ptr_sz)

            name = memory_helpers.read_utf8(mu, ptr_name)
            signature = memory_helpers.read_utf8(mu, ptr_sign)

            pyclazz.register_native(name, signature, ptr_func)

        return JNI_OK

    @native_method
    def unregister_natives(self, mu, env):
        raise NotImplementedError()

    @native_method
    def monitor_enter(self, mu, env):
        raise NotImplementedError()

    @native_method
    def monitor_exit(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_java_vm(self, mu, env, vm):
        logger.debug("JNIEnv->GetJavaVM(0x%08x) was called" % vm)

        mu.mem_write(vm, self._emu.java_vm.address_ptr.to_bytes(4, byteorder='little'))

        return JNI_OK

    @native_method
    def get_string_region(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_string_utf_region(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_primitive_array_critical(self, mu, env):
        raise NotImplementedError()

    @native_method
    def release_primitive_array_critical(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_string_critical(self, mu, env):
        raise NotImplementedError()

    @native_method
    def release_string_critical(self, mu, env):
        raise NotImplementedError()

    @native_method
    def new_weak_global_ref(self, mu, env):
        raise NotImplementedError()

    @native_method
    def delete_weak_global_ref(self, mu, env):
        raise NotImplementedError()

    @native_method
    def exception_check(self, mu, env):
        """
        Returns JNI_TRUE when there is a pending exception; otherwise, returns JNI_FALSE.
        """
        #logger.debug("JNIEnv->ExceptionCheck() was called")
        # TODO: Implement
        return JNI_FALSE

    @native_method
    def new_direct_byte_buffer(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_direct_buffer_address(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_direct_buffer_capacity(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_object_ref_type(self, mu, env):
        raise NotImplementedError()
