from .keystone_in import Ks, KS_ARCH_ARM, KS_MODE_THUMB, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from .const import emu_const
import sys
import traceback
import logging


# Utility class to create a bridge between ARM and Python.
class Hooker:

    """
    :type emu androidemu.emulator.Emulator
    """
    def __init__(self, emu, base_addr, size):
        self._emu = emu
        arch = emu.get_arch()
        self._size = size
        self._current_id = 0xFF00
        self._hooks = dict()
        _hook_start = base_addr + emu.get_ptr_size()
        self._hook_current = _hook_start
        self._emu.mu.hook_add(UC_HOOK_CODE, self._hook, None, _hook_start, _hook_start + size)
    #

    def _get_next_id(self):
        idx = self._current_id
        self._current_id += 1
        return idx

    #返回function首地址，如果是thumb指令，自动+1
    def write_function(self, func):
        # Get the hook id.
        hook_id = self._get_next_id()
        self._hooks[hook_id] = func
        #the the hook_id to header
        self._emu.mu.mem_write(self._hook_current, int(hook_id).to_bytes(4, byteorder='little', signed=False))
        self._hook_current+=4
        
        hook_addr = self._hook_current
        if (self._emu.get_arch() == emu_const.ARCH_ARM32):
            # Create the ARM assembly code.
            # 注意，这里不要改sp，因为后面hook code会靠sp来定位参数
            # Write assembly code to the emulator.
            self._emu.mu.mem_write(self._hook_current, b"\x1E\xFF\x2F\xE1")  #bx lr
            self._hook_current += 4
        else:
            self._emu.mu.mem_write(self._hook_current, b"\xC0\x03\x5F\xD6")  #ret
            self._hook_current += 4 
        #

        return hook_addr
    #

    def write_function_table(self, table):
        if not isinstance(table, dict):
            raise ValueError("Expected a dictionary for the function table.")

        index_max = int(max(table, key=int)) + 1

        # First, we write every function and store its result address.
        hook_map = dict()

        for index, func in table.items():
            hook_map[index] = self.write_function(func)

        # Then we write the function table.
        table_bytes = b""
        table_address = self._hook_current
        ptr_size = self._emu.get_ptr_size()
        for index in range(0, index_max):
            address = hook_map[index] if index in hook_map else 0
            table_bytes += int(address).to_bytes(ptr_size, byteorder='little')  #把每个函数指针写到指针表里面
        #

        self._emu.mu.mem_write(table_address, table_bytes)
        self._hook_current += len(table_bytes)

        # Then we write the a pointer to the table.指向table的指针，写在table的后面
        ptr_address = self._hook_current
        self._emu.mu.mem_write(ptr_address, table_address.to_bytes(ptr_size, byteorder='little'))
        self._hook_current += ptr_size

        return ptr_address, table_address
    #

    def _hook(self, mu, address, size, user_data):
        #通过hook一条特殊的指令回调到python处理
        #FIXME : 这里有隐晦的bug，如果在触发hook的指令刚好被调度器打断，则这个回调会正常执行，但是执行后会修改状态，比如函数调用改了r0等返回值
        #而unicorn恢复调用时候会再次触发该回调，相当于这个回调同时触发了两次，但是此时的上下文已经被上次的调用改掉了，导致这次调用的上下文是错的
        #如果调度器采用指令数量中断容易有可能出现这个问题(emu_start第四个参数)
        #总结目前局限，不要在hook_code内部调用emu_stop
        arch = self._emu.get_arch()
        #所有hook_id就在这条指令的前四个四节
        hook_id_ptr = address - 4
        hook_id_bytes = mu.mem_read(hook_id_ptr, 4)
        hook_id = int.from_bytes(hook_id_bytes, byteorder='little', signed=False)

        hook_func = self._hooks[hook_id]
        #logging.debug("hook_id:%d, hook_func:%r"%(hook_id, hook_func))

        # Call hook.
        try:
            hook_func(self._emu)
        except Exception as e:
            # Make sure we catch exceptions inside hooks and stop emulation.
            mu.emu_stop()
            traceback.print_exc()
            logging.exception("catch error on _hook")
            sys.exit(-1)
            raise
        #
    #
