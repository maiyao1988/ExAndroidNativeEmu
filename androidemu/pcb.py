import logging
import os
import time
import importlib
import inspect
import pkgutil
from random import randint
from .vfs.virtual_file import VirtualFile
import sys

#模仿进程控制块信息
#process all info get be get from here including fd etc
class Pcb:
    def __init__(self):
        self._fds = {}
        self._fds[sys.stdin.fileno()] = VirtualFile('stdin', sys.stdin.fileno())
        self._fds[sys.stdout.fileno()] = VirtualFile('stdout', sys.stdout.fileno())
        self._fds[sys.stderr.fileno()] = VirtualFile('stderr', sys.stderr.fileno())
    #

    def get_pid(self):
        return os.getpid()
    #

    def add_fd(self, name, name_in_system, fd):
        self._fds[fd] = VirtualFile(name, fd, name_in_system=name_in_system)
        return fd
    #

    def get_fd_detail(self, fd):
        return self._fds[fd]
    #

    def has_fd(self, fd):
        return fd in self._fds
    #
    
    def remove_fd(self, fd):
        self._fds.pop(fd)
    #
#

_pcb = Pcb()
def get_pcb():
    global _pcb
    return _pcb
#