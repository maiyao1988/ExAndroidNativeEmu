import logging
import os
import time
import importlib
import inspect
import pkgutil
from random import randint

#模仿进程控制块信息
#process all info get be get from here including fd etc
class Pcb:
    def get_pid(self):
        return os.getpid()
    #
#
_pcb = Pcb()
def get_pcb():
    global _pcb
    return _pcb
#