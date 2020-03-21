import logging
import os
import posixpath

from androidemu.const.linux import *
from androidemu.config import WRITE_FSTAT_TIMES
from androidemu.cpu.syscall_handlers import SyscallHandlers
from androidemu.utils import memory_helpers
from androidemu.vfs import file_helpers
import androidemu.utils.misc_utils
import platform
g_isWin = platform.system() == "Windows"
if not g_isWin:
    import fcntl
#
logger = logging.getLogger(__name__)

OVERRIDE_URANDOM = False
OVERRIDE_URANDOM_BYTE = b"\x00"


class VirtualFile:

    def __init__(self, name, file_descriptor, name_in_system=None):
        self.name = name
        self.name_in_system = name_in_system
        self.descriptor = file_descriptor
    #
#


class VirtualFileSystem:

    """
    :type syscall_handler SyscallHandlers
    """
    def __init__(self, root_path, syscall_handler, memory_map):
        self._root_path = root_path
        self.__memory_map = memory_map

        # TODO: Improve fd logic.
        self._file_descriptor_counter = 3
        self._virtual_files = dict()
        self._virtual_files[0] = VirtualFile('stdin', 0)
        self._virtual_files[1] = VirtualFile('stdout', 1)
        self._virtual_files[2] = VirtualFile('stderr', 2)

        syscall_handler.set_handler(0x3, "read", 3, self._handle_read)
        syscall_handler.set_handler(0x4, "write", 3, self._handle_write)
        syscall_handler.set_handler(0x5, "open", 3, self._handle_open)
        syscall_handler.set_handler(0x6, "close", 1, self._handle_close)
        syscall_handler.set_handler(0x0A, "unlink", 1, self._handle_unlink)
        syscall_handler.set_handler(0x13, "lseek", 3, self._handle_lseek)
        syscall_handler.set_handler(0x21, "access", 2, self._handle_access)
        syscall_handler.set_handler(0x27, "mkdir", 2, self.__mkdir)
        syscall_handler.set_handler(0x36, "ioctl", 6, self.__ioctl)
        syscall_handler.set_handler(0x37, "fcntl", 6, self.__fcntl64)
        syscall_handler.set_handler(0x92, "writev", 3, self._handle_writev)
        syscall_handler.set_handler(0xC5, "fstat64", 2, self._handle_fstat64)
        syscall_handler.set_handler(0xDD, "fcntl64", 6, self.__fcntl64)
        syscall_handler.set_handler(0x10A, "statfs64", 3, self.__statfs64)
        syscall_handler.set_handler(0x142, "openat", 4, self._handle_openat)
        syscall_handler.set_handler(0x147, "fstatat64", 4, self._handle_fstatat64)

    def translate_path(self, filename):
        return androidemu.utils.misc_utils.vfs_path_to_system_path(self._root_path, filename)
    #
    
    def _store_fd(self, name, name_in_system, file_descriptor):
        next_fd = self._file_descriptor_counter
        self._file_descriptor_counter += 1
        self._virtual_files[next_fd] = VirtualFile(name, file_descriptor, name_in_system=name_in_system)
        return next_fd

    def _open_file(self, filename, mode):
        #define O_RDONLY 00000000
        #define O_WRONLY 00000001
        #define O_RDWR 00000002
        #ifndef O_CREAT
        #define O_CREAT 00000100
        # Special cases, such as /dev/urandom.

        if filename == '/dev/urandom':
            logger.info("File opened '%s'" % filename)
            return self._store_fd('/dev/urandom', None, 'urandom')
        #

        file_path = self.translate_path(filename)
        if (filename.startswith("/proc/")):
            #simulate proc file system
            parent = os.path.dirname(file_path)
            if (not os.path.exists(parent)):
                os.makedirs(parent)
            #
            #TODO: move pid to config
            map_paths = ("/proc/%d/maps"%0x1122, "/proc/self/maps")
            if (filename in map_paths):
                with open(file_path, "w") as f:
                    self.__memory_map.dump_maps(f)
                #
            #
        #

        if os.path.isfile(file_path):
            logger.info("File opened '%s'" %filename)
            flags = os.O_RDWR
            if hasattr(os, "O_BINARY"):
                flags |= os.O_BINARY
            if (mode & 100):
                flags | os.O_CREAT
            #
            if (mode & 2000):
                flags | os.O_APPEND
            #
            return self._store_fd(filename, file_path, androidemu.utils.misc_utils.my_open(file_path, flags))
        else:
            logger.warning("File does not exist '%s'" % filename)
            return -1

    def _handle_read(self, mu, fd, buf_addr, count):
        """
        ssize_t read(int fd, void *buf, size_t count);

        On files that support seeking, the read operation commences at the current file offset, and the file offset
        is incremented by the number of bytes read. If the current file offset is at or past the end of file,
        no bytes are read, and read() returns zero.

        If count is zero, read() may detect the errors described below. In the absence of any errors, or if read()
        does not check for errors, a read() with a count of 0 returns zero and has no other effects.

        If count is greater than SSIZE_MAX, the result is unspecified.
        """
        if fd <= 2:
            logging.warning("skip read for fd %d"%fd)
            return 0
            #raise NotImplementedError("Unsupported read operation for file descriptor %d." % fd)
        #
        if fd not in self._virtual_files:
            # TODO: 重构，写到socket fd里面的都是合法的
            #raise NotImplementedError()
            return 0
        #

        file = self._virtual_files[fd]

        logger.info("Reading %d bytes from '%s'" % (count, file.name))

        if file.descriptor == 'urandom':
            if OVERRIDE_URANDOM:
                buf = OVERRIDE_URANDOM_BYTE * count
            else:
                buf = os.urandom(count)
        else:
            buf = os.read(file.descriptor, count)

        result = len(buf)
        mu.mem_write(buf_addr, buf)
        return result

    def _handle_write(self, mu, fd, buf_addr, count):
        
        data = mu.mem_read(buf_addr, count)
        if (fd == 1):
            s = bytes(data).decode("utf-8")
            logger.info("stdout:[%s]"%s)
            return len(data)
        elif(fd == 2):
            s = bytes(data).decode("utf-8")
            logger.warning("stderr:[%s]"%s)
            return len(data)
        #

        if fd not in self._virtual_files:
            # TODO: 重构，写到socket fd里面的都是合法的
            logging.info("write to fd %x data:%r"%(fd, data))
            return count
            #raise NotImplementedError()

        file = self._virtual_files[fd]
        try:
            r = os.write(file.descriptor, data)
        except OSError as e:
            logger.warning("File write '%s' error %r skip" %(file.name, e))
            return 0
        #
        return r
    #

    def _handle_open(self, mu, filename_ptr, flags, mode):
        """
        int open(const char *pathname, int flags, mode_t mode);

        return the new file descriptor, or -1 if an error occurred (in which case, errno is set appropriately).
        """
        filename = memory_helpers.read_utf8(mu, filename_ptr)

        return self._open_file(filename, mode)

    def _handle_close(self, mu, fd):
        """
        int close(int fd);

        close() closes a file descriptor, so that it no longer refers to any file and may be reused. Any record locks
        (see fcntl(2)) held on the file it was associated with, and owned by the process, are removed (regardless of
        the file descriptor that was used to obtain the lock).

        close() returns zero on success. On error, -1 is returned, and errno is set appropriately.
        """
        if fd not in self._virtual_files:
            return 0

        file = self._virtual_files[fd]

        if file.descriptor != 'urandom':
            logger.info("File closed '%s'" % file.name)
            try:
                os.close(file.descriptor)
            except OSError as e:
                logger.warning("File closed '%s' error %r skip" %(file.name, e))
                return -1
            #
        else:
            logger.info("File closed '%s'" % '/dev/urandom')
        #
        return 0
    
    def _handle_unlink(self, mu, path_ptr):
        path = memory_helpers.read_utf8(mu, path_ptr)
        vfs_path = self.translate_path(path)
        logger.info("unlink call path [%s]"%path)
        return 0
    #

    def _handle_lseek(self, mu, fd, offset, whence):
        if fd not in self._virtual_files:
            raise RuntimeError("fd %d not opened"%(fd,))
            #for debug
        #
        file = self._virtual_files[fd]
        return os.lseek(file.descriptor, offset, whence)
    #

    def _handle_access(self, mu, filename_ptr, flags):
        filename = memory_helpers.read_utf8(mu, filename_ptr)
        logger.warning("Path '%s'" % filename)
        return 0
    #
    def __mkdir(self, mu, path_ptr, mode):
        path = memory_helpers.read_utf8(mu, path_ptr)
        vfs_path = self.translate_path(path)

        logger.info("mkdir call path [%s]"%path)
        if (not os.path.exists(vfs_path)):
            os.makedirs(vfs_path)
        #
        return 0
    #

    def _handle_writev(self, mu, fd, vec, vlen):
        if fd == 2:
            for i in range(0, vlen):
                addr = memory_helpers.read_ptr(mu, (i * 8) + vec)
                size = memory_helpers.read_ptr(mu, (i * 8) + vec + 4)
                data = bytes(mu.mem_read(addr, size)).decode(encoding='UTF-8')

                logger.error('Writev %s' % data)

            return 0

        raise NotImplementedError()

    def _handle_fstat64(self, mu, fd, buf_ptr):
        """
        These functions return information about a file. No permissions are required on the file itself, but-in the
        case of stat() and lstat() - execute (search) permission is required on all of the directories in path that
        lead to the file.

        fstat() is identical to stat(), except that the file to be stat-ed is specified by the file descriptor fd.
        """
        if fd not in self._virtual_files:
            return -1

        file = self._virtual_files[fd]
        logger.info("File stat64 '%s'" % file.name)

        stat = file_helpers.stat64(file.name_in_system)
        # stat = os.fstat(file.descriptor)
        file_helpers.stat_to_memory(mu, buf_ptr, stat, WRITE_FSTAT_TIMES)

        return 0
    #

    def __ioctl(self, mu, fd, cmd, arg1, arg2, arg3, arg4):
        #http://man7.org/linux/man-pages/man2/ioctl_list.2.html
        #0x00008912   SIOCGIFCONF      struct ifconf *
        #TODO:ifconf struct is complex, implement it
        SIOCGIFCONF = 0x00008912
        logging.info("%x %x %x"%(fd, cmd, arg1))
        if (cmd == SIOCGIFCONF):
            #this is a way to get network address
            logging.info("warning ioctl SIOCGIFCONF to get net addrs not implemented return -1 and skip")
            return -1
        #
        raise NotImplementedError()
    #

    def __fcntl64(self, mu, fd, cmd, arg1, arg2, arg3, arg4):
        #fcntl is not support on windows
        global g_isWin
        if (g_isWin):
            return 0
        if (fd in self._virtual_files):
            if (F_GETFL == cmd):
                return fcntl.fcntl(fd, cmd)
            elif(F_SETFL == cmd):
                return fcntl.fcntl(fd, cmd, arg1)
        #
        raise NotImplementedError()
    #

    def __statfs64(self, mu, path, sz, buf):
        #TODO
        return -1
    #

    def _handle_openat(self, mu, dfd, filename_ptr, flags, mode):
        """
        int openat(int dirfd, const char *pathname, int flags, mode_t mode);

        On success, openat() returns a new file descriptor.
        On error, -1 is returned and errno is set to indicate the error.

        EBADF
            dirfd is not a valid file descriptor.
        ENOTDIR
            pathname is relative and dirfd is a file descriptor referring to a file other than a directory.
        """
        filename = memory_helpers.read_utf8(mu, filename_ptr)

        if not filename.startswith("/") and dfd != 0:
            raise NotImplementedError("Directory file descriptor has not been implemented yet.")

        return self._open_file(filename, mode)

    def _handle_fstatat64(self, mu, dirfd, pathname_ptr, buf, flags):
        """
        int fstatat(int dirfd, const char *pathname, struct stat *buf, int flags);

        If the pathname given in pathname is relative, then it is interpreted relative to the directory referred
        to by the file descriptor dirfd (rather than relative to the current working directory of the calling process,
        as is done by stat(2) for a relative pathname).

        If pathname is relative and dirfd is the special value AT_FDCWD,
        then pathname is interpreted relative to the current working directory of the calling process (like stat(2)).

        If pathname is absolute, then dirfd is ignored.

        flags can either be 0, or include one or more of the following flags ..

        On success, fstatat() returns 0. On error, -1 is returned and errno is set to indicate the error.
        """
        pathname = memory_helpers.read_utf8(mu, pathname_ptr)

        if not pathname.startswith('/'):
            raise NotImplementedError("Directory file descriptor has not been implemented yet.")

        if not flags == 0:
            if flags & 0x100:  # AT_SYMLINK_NOFOLLOW
                pass
            if flags & 0x800:  # AT_NO_AUTOMOUNT
                pass
            # raise NotImplementedError("Flags has not been implemented yet.")

        logger.info("File fstatat64 '%s'" % pathname)
        pathname = self.translate_path(pathname)

        if not os.path.exists(pathname):
            logger.warning('> File was not found.')
            return -1

        logger.warning('> File was found.')

        stat = file_helpers.stat64(path=pathname)
        # stat = os.stat(path=file_path, dir_fd=None, follow_symlinks=False)
        file_helpers.stat_to_memory(mu, buf, stat, WRITE_FSTAT_TIMES)

        return 0
