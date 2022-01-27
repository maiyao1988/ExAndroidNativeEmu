import inspect
import itertools
import logging
from .jvm_id_conter import *

logger = logging.getLogger(__name__)

#Class函数实现基本原则：
#1.所有python函数(包括__init__)传入传出参数能用python基本类型表示的，一律用python类型表示，例如字符串用pystring，整数为用1
#2.所有模拟的java函数（java_method_def修饰的函数）除八个基本类型外， 传入传出都是java类型，例如字符串用String，整数用Integer，注意区分Integer和Int，Integer是对象不属于八个基本类型，
#3.需要看函数返回值签名分析，如果是八个基本类型，用python整数代表java整数，用python float代表java double和float
class JavaClassDef(type):
    
    def __init__(cls, name, base, ns, jvm_name=None, jvm_fields=None, jvm_ignore=False, jvm_super=None):
        cls.jvm_id = next_cls_id()
        cls.jvm_name = jvm_name
        cls.jvm_methods = dict()
        cls.jvm_fields = dict()
        cls.jvm_ignore = jvm_ignore
        cls.jvm_super = jvm_super
        cls.class_object = None

        # Register all defined Java methods.
        for func in inspect.getmembers(cls, predicate=inspect.isfunction):
            if hasattr(func[1], 'jvm_method'):
                method = func[1].jvm_method
                cls.jvm_methods[method.jvm_id] = method
            #
        #
        # Register all defined Java fields.
        if jvm_fields is not None:
            for jvm_field in jvm_fields:
                cls.jvm_fields[jvm_field.jvm_id] = jvm_field
        #
        type.__init__(cls, name, base, ns)
    #

    def __new__(cls, name, base, ns, **kargs):
        return type.__new__(cls, name, base, ns)
    #

    def register_native(cls, name, signature, ptr_func):
        found = False
        found_method = None

        # Search for a defined jvm method.
        for method in cls.jvm_methods.values():
            if method.name == name and method.signature == signature:
                method.native_addr = ptr_func
                found = True
                found_method = method
                break

        if not found:
            x = "Register native ('%s', '%s', '0x%08X') failed on class %s." % (name, signature, ptr_func, cls.__name__)
            logger.warning(x)
            return
            # raise RuntimeError("Register native ('%s', '%s') failed on class %s." % (name, signature, cls.__name__))
        logger.debug("Registered native function ('%s', '%s', ''0x%08X'') to %s.%s" % (name, signature, ptr_func,
                                                                           cls.__name__, found_method.func_name))
    #
    
    def find_method(cls, name, signature):
        for method in cls.jvm_methods.values():
            if method.name == name and method.signature == signature:
                return method
            #
        #
        if (cls.jvm_super is not None):
            return cls.jvm_super.find_method(name, signature)
        #
        return None
    #

    #用于支持java反射，java反射签名都没有返回值
    #@param signature_no_ret something like (ILjava/lang/String;) 注意，没有返回值
    def find_method_sig_with_no_ret(cls, name, signature_no_ret):
        assert signature_no_ret[0] == "(" and signature_no_ret[len(signature_no_ret)-1] == ")", "signature_no_ret error"
        for method in cls.jvm_methods.values():
            if method.name == name and method.signature.startswith(signature_no_ret):
                return method
            #
        #
        if (cls.jvm_super is not None):
            return cls.jvm_super.find_method_sig_with_no_ret(name, signature_no_ret)
        #
        return None
    #


    def find_method_by_id(cls, jvm_id):
        if (jvm_id in cls.jvm_methods):
            return cls.jvm_methods[jvm_id]
        if cls.jvm_super is not None:
            return cls.jvm_super.find_method_by_id(jvm_id)
        #
        return None
    #

    def find_field(cls, name, signature, is_static):
        for field in cls.jvm_fields.values():
            if field.name == name and field.signature == signature and field.is_static == is_static:
                return field
            #
        #
        if (cls.jvm_super is not None):
            return cls.jvm_super.find_field(name, signature, is_static)
        #

        return None

    def find_field_by_id(cls, jvm_id):
        if (jvm_id in cls.jvm_fields):
            return cls.jvm_fields[jvm_id]
        if cls.jvm_super is not None:
            return cls.jvm_super.find_field_by_id(jvm_id)
        #
        return None
    #
