from unicorn import Uc, UC_PROT_READ, UC_PROT_WRITE
from androidemu.cpu.syscall_handlers import SyscallHandlers
from androidemu.native.memory_heap import UnicornSimpleHeap
import os

class NativeMemory:

    """
    :type mu Uc
    :type syscall_handler SyscallHandlers
    """
    def __init__(self, mu, memory, syscall_handler, file_system):
        self._mu = mu
        self._file_system = file_system
        self._memory = memory
        self._syscall_handler = syscall_handler
        self._syscall_handler.set_handler(0x5B, "munmap", 2, self._handle_munmap)
        self._syscall_handler.set_handler(0x7D, "mprotect", 3, self._handle_mprotect)
        self._syscall_handler.set_handler(0xC0, "mmap2", 6, self._handle_mmap2)
        self._syscall_handler.set_handler(0xDC, "madvise", 3, self._handle_madvise)

    def allocate(self, length, prot=UC_PROT_READ | UC_PROT_WRITE):
        return self._memory.map(0, length, prot)

    def _handle_munmap(self, uc, addr, len_in):
        self._memory.unmap(addr, len_in)

    def _handle_mmap2(self, mu, addr, length, prot, flags, fd, offset):
        """
        void *mmap2(void *addr, size_t length, int prot, int flags, int fd, off_t pgoffset);
        """

        addr = self._memory.map(addr, length, prot)
        # MAP_FILE	    0
        # MAP_SHARED	0x01
        # MAP_PRIVATE	0x02
        # MAP_FIXED	    0x10
        # MAP_ANONYMOUS	0x20
        if fd != 0xffffffff: # 如果有fd
            if fd <= 2:
                raise NotImplementedError("Unsupported read operation for file descriptor %d." % fd)
            #
            if fd not in self._file_system._file_descriptors:
                # TODO: Return valid error.
                raise NotImplementedError()

            fd = self._file_system._file_descriptors[fd]
            data = os.read(fd.descriptor.read, length)
            self._mu.mem_write(addr, data)
        #
        return addr
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
        self._memory.protect(addr, len_in, prot)
        return 0
