from unicorn import Uc, UC_PROT_READ, UC_PROT_WRITE
from ..cpu.syscall_handlers import SyscallHandlers
from .memory_map import MemoryMap
from ..const import emu_const
from .. import pcb
import logging
import os

class MemorySyscallHandler:
    """
    :type mu Uc
    :type syscall_handler SyscallHandlers
    """
    def __init__(self, emu, memory, syscall_handler):
        self.__emu = emu
        self.__pcb = emu.get_pcb()
        self._memory = memory
        self._syscall_handler = syscall_handler
        if (self.__emu.get_arch() == emu_const.ARCH_ARM32):
            self._syscall_handler.set_handler(0x2d, "brk", 1, self._handle_brk)
            self._syscall_handler.set_handler(0x5B, "munmap", 2, self._handle_munmap)
            self._syscall_handler.set_handler(0x7D, "mprotect", 3, self._handle_mprotect)
            self._syscall_handler.set_handler(0xC0, "mmap2", 6, self._handle_mmap2)
            self._syscall_handler.set_handler(0xDC, "madvise", 3, self._handle_madvise)
        else:
            #arm64
            self._syscall_handler.set_handler(0xd6, "brk", 1, self._handle_brk)
            self._syscall_handler.set_handler(0xd7, "munmap", 2, self._handle_munmap)
            self._syscall_handler.set_handler(0xe2, "mprotect", 3, self._handle_mprotect)
            #arm64 只有mmap调用，没有mmap2
            self._syscall_handler.set_handler(0xde, "mmap", 6, self._handle_mmap)
            self._syscall_handler.set_handler(0xe9, "madvise", 3, self._handle_madvise)
        #
    #
    
    def _handle_brk(self, uc, brk):
        #TODO: set errno
        #TODO: implement 
        return -1
    #

    def _handle_munmap(self, uc, addr, len_in):
        #TODO: set errno
        return self._memory.unmap(addr, len_in)
    #

    def _handle_mmap2(self, mu, addr, length, prot, flags, fd, pgoffset):
        """
        void *mmap2(void *addr, size_t length, int prot, int flags, int fd, off_t pgoffset);
        """
        #define	PROT_READ	0x04	/* pages can be read */
        #define	PROT_WRITE	0x02	/* pages can be written */
        #define	PROT_EXEC	0x01	/* pages can be executed */
        #define MAP_SHARED 0x01
        #define MAP_PRIVATE 0x02
        #define MAP_TYPE 0x0f
        #define MAP_FIXED 0x10
        MAP_ANONYMOUS = 0x20
        #define MAP_UNINITIALIZED 0x0
        res = None
        if flags & MAP_ANONYMOUS:
            res = self._memory.map(addr, length, prot)
        elif fd != 0xffffffff: # 如果有fd
            if fd <= 2:
                raise NotImplementedError("Unsupported read operation for file descriptor %d." % fd)
            #
            if not self.__pcb.has_fd(fd):
                # TODO: Return valid error.
                raise NotImplementedError()

            vf = self.__pcb.get_fd_detail(fd)
            #mmap2 系统调用最后一个参数与mmap不同,注意阅读下面一句话!
            '''
            The mmap2() system call provides the same interface as mmap(2),
            except that the final argument specifies the offset into the file in
            4096-byte units (instead of bytes, as is done by mmap(2)).  This
            enables applications that use a 32-bit off_t to map large files (up
            to 2^44 bytes).
            '''
            offset = pgoffset * 4096
            res = self._memory.map(addr, length, prot, vf, offset)
        #
        else:
            res = self._memory.map(addr, length, prot)
        #
        logging.debug("mmap return 0x%08X"%res)
        return res
    #

    def _handle_mmap(self, mu, addr, length, prot, flags, fd, offset):
        """
        void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
        """
        #define	PROT_READ	0x04	/* pages can be read */
        #define	PROT_WRITE	0x02	/* pages can be written */
        #define	PROT_EXEC	0x01	/* pages can be executed */
        #define MAP_SHARED 0x01
        #define MAP_PRIVATE 0x02
        #define MAP_TYPE 0x0f
        #define MAP_FIXED 0x10
        
        MAP_ANONYMOUS = 0x20
        #define MAP_UNINITIALIZED 0x0
        res = None
        if flags & MAP_ANONYMOUS:
            res = self._memory.map(addr, length, prot)
        elif fd != 0xffffffff: # 如果有fd
            if fd <= 2:
                raise NotImplementedError("Unsupported read operation for file descriptor %d." % fd)
            #
            if not self.__pcb.has_fd(fd):
                # TODO: Return valid error.
                raise NotImplementedError()

            vf = self.__pcb.get_fd_detail(fd)
            res = self._memory.map(addr, length, prot, vf, offset)
        #
        else:
            res = self._memory.map(addr, length, prot)
        #
        logging.debug("mmap return 0x%016X"%res)
        return res
    #

    def _handle_madvise(self, mu, start, len_in, behavior):
        """
        int madvise(void *addr, size_t length, int advice);
        The kernel is free to ignore the advice.
        On success madvise() returns zero. On error, it returns -1 and errno is set appropriately.
        """
        # We don't need your advise.
        return 0

    def _handle_mprotect(self, mu, addr, len_in, prot):
        """
        int mprotect(void *addr, size_t len, int prot);

        mprotect() changes protection for the calling process's memory page(s) containing any part of the address
        range in the interval [addr, addr+len-1]. addr must be aligned to a page boundary.
        """
        return self._memory.protect(addr, len_in, prot)
    #
