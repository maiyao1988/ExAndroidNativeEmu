import logging
import os
import time
import importlib
import inspect
import pkgutil
import sys
import os.path
import time

from random import randint

from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from . import config
from . import pcb
from .const import emu_const
from .utils import misc_utils

class Task:
    def __init__(self):
        self.entry = 0
        self.context = None
        self.tid = 0
        self.init_stack_ptr = 0
        self.tls_ptr = 0
        #是否第一次调用
        self.is_init = True
        self.is_main = False
        self.is_exit = False
        #the time ts for prev halt, in ms
        self.halt_ts = -1
        #the timeout for blocking -1 is infinte
        self.blocking_timeout = -1
    #
#

class Scheduler:


    def __init__(self, emu):
        self.__emu = emu
        self.__mu = self.__emu.mu
        self.__pid = self.__emu.get_pcb().get_pid()
        self.__next_sub_tid = self.__pid + 1
        self.__ordered_tasks_list = []
        self.__tasks_map = {}
        self.__defer_task_map = {}
        self.__tid_2_remove = set()
        self.__cur_tid = 0

        self.__emu.memory.map(config.STOP_MEMORY_BASE, config.STOP_MEMORY_SIZE, UC_PROT_READ | UC_PROT_EXEC)
        self.__stop_pos = config.STOP_MEMORY_BASE

        #blocking futex ptr to thread lists, 
        #记录在futex中等待的任务id
        self.__futex_blocking_map = {}
        #just record all blocking tid
        self.__blocking_set = set()
    #

    def __get_pc(self):
        if (self.__emu.get_arch() == emu_const.ARCH_ARM32):
            pc = self.__emu.mu.reg_read(UC_ARM_REG_PC)
            return pc
        else:
            return self.__emu.mu.reg_read(UC_ARM64_REG_PC)
        #
    #

    def __clear_reg0(self):
        
        if (self.__emu.get_arch() == emu_const.ARCH_ARM32):
            self.__mu.reg_write(UC_ARM_REG_R0, 0)
        else:
            self.__mu.reg_write(UC_ARM64_REG_X0, 0)
        #
    #

    def __set_sp(self, sp):
        if (self.__emu.get_arch() == emu_const.ARCH_ARM32):
            self.__emu.mu.reg_write(UC_ARM_REG_SP, sp)
        else:
            self.__emu.mu.reg_write(UC_ARM64_REG_SP, sp)
        #
    #

    def __set_tls(self, tls_ptr):
        if (self.__emu.get_arch() ==  emu_const.ARCH_ARM32):
            self.__emu.mu.reg_write(UC_ARM_REG_C13_C0_3, tls_ptr)
        else:
            self.__emu.mu.reg_write(UC_ARM64_REG_TPIDR_EL0, tls_ptr)
    #

    def __get_interrupted_entry(self):
        pc = self.__get_pc()
        if (self.__emu.get_arch() == emu_const.ARCH_ARM32):
            cpsr = self.__emu.mu.reg_read(UC_ARM_REG_CPSR)
            if (cpsr & (1<<5)):
                pc = pc | 1
            #
        #
        return pc
    #

    def __create_task(self, tid, stack_ptr, context, is_main, tls_ptr):
        t = Task()
        t.tid = tid
        t.init_stack_ptr = stack_ptr
        t.context = context
        t.is_main = is_main
        t.tls_ptr = tls_ptr
        return t
    #

    def __set_main_task(self):
        tid = self.__emu.get_pcb().get_pid()
        if (tid in self.__tasks_map):
            raise RuntimeError("set_main_task fail for main task %d exist!!!"%tid)
        #
        t = self.__create_task(tid, 0, None, True, 0)
        self.__tasks_map[tid] = t
        self.__ordered_tasks_list.append(tid)
    #

    def sleep(self, ms):
        tid = self.__cur_tid
        self.__blocking_set.add(tid)
        self.__tasks_map[tid].blocking_timeout = ms
        self.yield_task()
    #

    def futex_wait(self, futex_ptr, timeout=-1):
        block_set = None
        if futex_ptr in self.__futex_blocking_map:
            block_set = self.__futex_blocking_map[futex_ptr]
        #
        else:
            block_set = set()
            self.__futex_blocking_map[futex_ptr] = block_set
        #
        tid = self.get_current_tid()
        block_set.add(tid)
        self.__blocking_set.add(tid)
        self.__tasks_map[tid].blocking_timeout = timeout

        #handle out control flow
        self.yield_task()
    #

    def futex_wake(self, futex_ptr):
        cur_tid = self.get_current_tid()

        if (futex_ptr in self.__futex_blocking_map):
            block_set = self.__futex_blocking_map[futex_ptr]
            if len(block_set) > 0:
                tid = block_set.pop()
                self.__blocking_set.remove(tid)
                logging.debug("%d futex_wake tid %d waiting in futex_ptr 0x%08X is unblocked"%(cur_tid, tid, futex_ptr))
                return True
            else:
                logging.info("%d futex_wake unblock nobody waiting in futex ptr 0x%08X"%(cur_tid, futex_ptr))
                return False
        #
        else:
            logging.info("%d futex_wake unblock nobody waiting in futex ptr 0x%08X"%(cur_tid, futex_ptr))
            return False
        #
 
    #

    #创建子线程任务
    def add_sub_task(self, stack_ptr, tls_ptr=0):
        tid = self.__next_sub_tid
        #保存当前执行的上下文
        ctx = self.__emu.mu.context_save()
        t = self.__create_task(tid, stack_ptr, ctx, False, tls_ptr)
        self.__defer_task_map[tid] = t
        self.__next_sub_tid = self.__next_sub_tid + 1
        return tid
    #

    def get_current_tid(self):
        return self.__cur_tid
    #

    #yield the task.
    def yield_task(self):
        logging.debug("tid %d yield"%self.__cur_tid)
        self.__emu.mu.emu_stop()
    #
    
    def exit_current_task(self):
        self.__tasks_map[self.__cur_tid].is_exit = True
        self.__tid_2_remove.add(self.__cur_tid)
        self.yield_task()
    #


    #@params entry the main_thread entry_point
    def exec(self, main_entry, clear_task_when_return=True):
        self.__set_main_task()
        if (self.__emu.get_arch() == emu_const.ARCH_ARM32):
            self.__emu.mu.reg_write(UC_ARM_REG_LR, self.__stop_pos)
        else:
            self.__emu.mu.reg_write(UC_ARM64_REG_X30, self.__stop_pos)
        #
        while True:
            for tid in reversed(self.__ordered_tasks_list):
                task = self.__tasks_map[tid]
                if (tid in self.__blocking_set):
                    #处理block
                    if (len(self.__ordered_tasks_list) == 1):
                        #只有主线程，而且被block
                        if (task.blocking_timeout < 0):
                            #只有一个线程且被无限期block，有bug
                            raise RuntimeError("only one task %d exists, but blocking infinity dead lock bug!!!!"%tid)
                        else:
                            #优化，如果仅仅只有一个线程block，而且有timeout，直接sleep就行了，因为再继续运行都是没意义的循环
                            logging.debug("only on task %d block with timeout %d ms do sleep"%(tid, task.blocking_timeout))
                            time.sleep(task.blocking_timeout/1000)
                            #sleep返回则完成block
                            self.__blocking_set.remove(tid)
                        #
                    #
                    else:
                        if task.blocking_timeout > 0:
                            now = int(time.time() * 1000)
                            if (now - task.halt_ts < task.blocking_timeout):
                                #仍然未睡够，继续睡
                                logging.debug("%d is blocking skip scheduling ts has block %d ms timeout %d ms"%(tid, now - task.halt_ts, task.blocking_timeout))
                                continue
                            else:
                                logging.debug("%d is wait up for timeout"%(tid, ))
                                task.blocking_timeout = -1
                                self.__blocking_set.remove(tid)
                                #睡够了，不跳过循环 继续执行调度
                        else:
                            #无限期block，直接跳过调度
                            logging.debug("%d is blocking skip scheduling"%(tid,))
                            continue
                        #
                    #
                #
                logging.debug("%d scheduling enter "%tid)

                self.__cur_tid = tid
                #run
                start_pos = 0
                if (task.is_main):
                    if (task.is_init):
                        start_pos = main_entry
                        task.is_init = False
                    #
                    else:
                        #上下文切换
                        self.__emu.mu.context_restore(task.context)
                        start_pos = self.__get_interrupted_entry()
                    #
                #
                else:
                    #子线程
                    #先恢复上下文
                    self.__emu.mu.context_restore(task.context)
                    start_pos = self.__get_interrupted_entry()

                    if (task.is_init):
                        #如果是第一次进入，需要设置child_stack指针
                        self.__set_sp(task.init_stack_ptr)
                        if (task.tls_ptr):
                            self.__set_tls(task.tls_ptr)
                        #第一次进入子线程，需要将r0清空成0，这里模仿linux clone子线程返回0的逻辑
                        self.__clear_reg0()
                        task.is_init = False
                    #
                    
                #

                #print(hex(start_pos))
                #加上uc timeout参数有bug，会随机崩溃，这个机制是uc内部使用多线程实现的，但uc对象根本不是线程安全的，指令数可以加，但是很慢
                #第四个参数传100执行arm64的android6 libc会触发bug，具体原因见hooker.py FIXME注释
                self.__emu.mu.emu_start(start_pos, self.__stop_pos, 0, 0)
                task.halt_ts = int(time.time()*1000)
                #after run
                ctx = self.__emu.mu.context_save()
                task.context = ctx

                #运行结束，任务标记成可删除
                if (self.__get_pc() == self.__stop_pos or task.is_exit):
                    self.__tid_2_remove.add(self.__cur_tid)
                    logging.debug("%d scheduling exit"%tid)
                #
                else:
                    logging.debug("%d scheduling paused"%tid)
                #
            #
            #在调度里面清掉退出的线程
            for tid in self.__tid_2_remove:
                self.__tasks_map.pop(tid)
                #FIXME slow delete, try to optimize
                self.__ordered_tasks_list.remove(tid)
            #
            self.__tid_2_remove.clear()

            for tid_defer in self.__defer_task_map:
                self.__tasks_map[tid_defer] = self.__defer_task_map[tid_defer]
                self.__ordered_tasks_list.append(tid_defer)
            #
            self.__defer_task_map.clear()

            if self.__pid not in self.__tasks_map:
                #主线程退出，退出调度循环
                logging.debug("main_thead tid [%d] exit exec return"%self.__pid)
                if (clear_task_when_return):
                    #clear all unfinished task
                    self.__tasks_map.clear()
                return
            #
        #
    #
#