from ..java_class_def import JavaClassDef
from ..java_field_def import JavaFieldDef
from ..java_method_def import java_method_def, JavaMethodDef
from ..constant_values import *
from ...utils import misc_utils
from .string import String

from xml.dom.minidom import parse
import xml.dom.minidom

class Editor(metaclass=JavaClassDef, jvm_name='android/content/SharedPreferences$Editor'):
    def __init__(self):
        pass
    #

    @java_method_def(name='putString', args_list=["jstring", "jstring"], signature='(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;', native=False)
    def putString(self, emu, skey, svalue):
        raise NotImplementedError()
    #

    @java_method_def(name='commit', signature='()Z', native=False)
    def commit(self, emu):
        raise NotImplementedError()
    #
#

class SharedPreferences(metaclass=JavaClassDef, jvm_name='android/content/SharedPreferences'):
    def __init__(self, emu, path):
        vfs_root = emu.get_vfs_root()
        real_path = misc_utils.vfs_path_to_system_path(vfs_root, path)
        self.__xml_tree = xml.dom.minidom.parse(real_path)
        self.__editor = Editor()
        self.__string_values = {}
        root = self.__xml_tree.documentElement
        string_node = root.getElementsByTagName("string")

        for node in string_node:
            if (node.hasAttribute("name")):
                k = node.getAttribute("name")
                v = str(node.childNodes[0].data)
                self.__string_values[k] = String(v)
            #
    #

    @java_method_def(name='edit', signature='()Landroid/content/SharedPreferences$Editor;', native=False)
    def edit(self, emu):
        return self.__editor
    #


    @java_method_def(name='getString', args_list=["jstring", "jstring"], signature='(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;', native=False)
    def getString(self, emu, skey, sdefault):
        pyKey = skey.get_py_string()
        if (pyKey in self.__string_values):
            return self.__string_values[pyKey]
        #
        else:
            return sdefault
        #
    #

#