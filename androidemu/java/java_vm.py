import logging
import traceback

from ..hooker import Hooker
from .helpers.native_method import native_method
from .jni_const import *
from .jni_env import JNIEnv

logger = logging.getLogger(__name__)


# https://docs.oracle.com/javase/7/docs/technotes/guides/jni/spec/invocation.html
# This class attempts to mimic the JNIInvokeInterface table.
class JavaVM:

    """
    :type class_loader JavaClassLoader
    :type hooker Hooker
    """
    def __init__(self, emu, class_loader, hooker):
        (self.address_ptr, self.address) = hooker.write_function_table({
            3: self.destroy_java_vm,
            4: self.attach_current_thread,
            5: self.detach_current_thread,
            6: self.get_env,
            7: self.attach_current_thread
        })

        self.jni_env = JNIEnv(emu, class_loader, hooker)
        self.__emu = emu
    #

    @native_method
    def destroy_java_vm(self, mu):
        raise NotImplementedError()
    #
    
    @native_method
    def attach_current_thread(self, mu, java_vm, env_ptr, thr_args):
        logger.debug("JavaVM->AttachCurrentThread(0x%08x, 0x%08x, 0x%08x)" %(java_vm, env_ptr, thr_args))
        mu.mem_write(env_ptr, self.jni_env.address_ptr.to_bytes(self.__emu.get_ptr_size(), byteorder='little'))
        return JNI_OK
    #

    @native_method
    def detach_current_thread(self, mu, java_vm):
        # TODO: NooOO idea.
        logger.debug("JavaVM->DetachCurrentThread(0x%08x)" %(java_vm,))
        return JNI_OK
    #

    @native_method
    def get_env(self, mu, java_vm, env_ptr, version):
        logger.debug("JavaVM->GetEnv(0x%08x, 0x%08x, 0x%08x)" %(java_vm, env_ptr, version))
        mu.mem_write(env_ptr, self.jni_env.address_ptr.to_bytes(self.__emu.get_ptr_size(), byteorder='little'))
        return JNI_OK
    #

    @native_method
    def attach_current_thread_as_daemon(self, mu, java_vm, env_ptr, thr_args):
        logger.debug("JavaVM->AttachCurrentThreadAsDaemon(0x%08x, 0x%08x, 0x%08x)" %(java_vm, env_ptr, thr_args))
        mu.mem_write(env_ptr, self.jni_env.address_ptr.to_bytes(self.__emu.get_ptr_size(), byteorder='little'))
        return JNI_OK
    #

