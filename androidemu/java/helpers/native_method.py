import inspect

from unicorn import Uc
from unicorn.arm_const import *

from ...hooker import STACK_OFFSET
from ..java_class_def import JavaClassDef
from ..jni_const import JNI_ERR
from ..jni_ref import jobject, jclass


def native_write_args(emu, *argv):
    amount = len(argv)

    if amount == 0:
        return

    if amount >= 1:
        native_write_arg_register(emu, UC_ARM_REG_R0, argv[0])

    if amount >= 2:
        native_write_arg_register(emu, UC_ARM_REG_R1, argv[1])

    if amount >= 3:
        native_write_arg_register(emu, UC_ARM_REG_R2, argv[2])

    if amount >= 4:
        native_write_arg_register(emu, UC_ARM_REG_R3, argv[3])

    if amount >= 5:
        sp_start = emu.mu.reg_read(UC_ARM_REG_SP)
        sp_current = sp_start - STACK_OFFSET  # Need to offset because our hook pushes one register on the stack.
        sp_current = sp_current - (4 * (amount - 4))  # Reserve space for arguments.
        sp_end = sp_current

        for arg in argv[4:]:
            emu.mu.mem_write(sp_current, native_translate_arg(emu, arg).to_bytes(4, byteorder='little'))
            sp_current = sp_current + 4

        emu.mu.reg_write(UC_ARM_REG_SP, sp_end)


def native_read_args(mu, args_count):
    native_args = []

    if args_count >= 1:
        native_args.append(mu.reg_read(UC_ARM_REG_R0))

    if args_count >= 2:
        native_args.append(mu.reg_read(UC_ARM_REG_R1))

    if args_count >= 3:
        native_args.append(mu.reg_read(UC_ARM_REG_R2))

    if args_count >= 4:
        native_args.append(mu.reg_read(UC_ARM_REG_R3))

    sp = mu.reg_read(UC_ARM_REG_SP)
    sp = sp + STACK_OFFSET  # Need to offset by 4 because our hook pushes one register on the stack.

    if args_count >= 5:
        for x in range(0, args_count - 4):
            native_args.append(int.from_bytes(mu.mem_read(sp + (x * 4), 4), byteorder='little'))

    return native_args


def native_translate_arg(emu, val):
    if isinstance(val, int):
        return val
    elif isinstance(val, bytearray):
        return emu.java_vm.jni_env.add_local_reference(jobject(val))
    elif isinstance(type(val), JavaClassDef):
        # TODO: Look into this, seems wrong..
        return emu.java_vm.jni_env.add_local_reference(jobject(val))
    elif isinstance(val, JavaClassDef):
        return emu.java_vm.jni_env.add_local_reference(jclass(val))
    else:
        raise NotImplementedError("Unable to write response '%s' type '%s' to emulator." % (str(val), type(val)))


def native_write_arg_register(emu, reg, val):
    emu.mu.reg_write(reg, native_translate_arg(emu, val))


def native_method(func):
    def native_method_wrapper(*argv):
        """
        :type self
        :type emu androidemu.emulator.Emulator
        :type mu Uc
        """

        emu = argv[1] if len(argv) == 2 else argv[0]
        mu = emu.mu

        args = inspect.getfullargspec(func).args
        args_count = len(args) - (2 if 'self' in args else 1)

        if args_count < 0:
            raise RuntimeError("NativeMethod accept at least (self, mu) or (mu).")

        native_args = native_read_args(mu, args_count)

        if len(argv) == 1:
            result = func(mu, *native_args)
        else:
            le = len(native_args)
            result = func(argv[0], mu, *native_args)

        if result is not None:
            if(isinstance(result, tuple)):
                #tuple作为特殊返回8字节数据约定
                rlow = result[0]
                rhigh = result[1]
                native_write_arg_register(emu, UC_ARM_REG_R0, rlow)
                native_write_arg_register(emu, UC_ARM_REG_R1, rhigh)
            else:
                #FIXME handle python基本类型str int float,处理返回值逻辑略为混乱，
                #返回值的问题统一在这里处理掉
                native_write_arg_register(emu, UC_ARM_REG_R0, result)
            #
        #
    #

    return native_method_wrapper