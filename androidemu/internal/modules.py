import logging

from unicorn import UC_PROT_ALL,UC_PROT_WRITE,UC_PROT_READ

from . import arm
from unicorn.arm_const import *
from unicorn.arm64_const import *
from ..utils.misc_utils import get_segment_protection,page_end, page_start
from ..utils.stack_helpers import StackHelper
from .module import Module
from ..const import emu_const
from ..utils import memory_helpers,misc_utils
from ..vfs.virtual_file import VirtualFile
from .. import config
from . import elf_reader
from ..const import linux
import os

logger = logging.getLogger(__name__)

class Modules:

    def __tls_init(self):
        sp_helpers = StackHelper(self.emu)

        pthread_internal_nptr = 0x400
        #为pthread_internal预留空间，由于这个结构体跟libc的版本相关，暂时什么都不写
        thread_internal_ptr = sp_helpers.reserve(pthread_internal_nptr)

        stack_guard_ptr = sp_helpers.write_val(0x1000)
        #print(hex(stack_guard_ptr))

        #argv的实际字符串，目前只写一个
        argvs = ["app_process32"]
        argvs_ptrs = []
        for argv in argvs:
            argv_str_ptr = sp_helpers.write_utf8(argv)
            argvs_ptrs.append(argv_str_ptr)
        #

        #TODO,从配置文件读取文件
        env = {
            "ANDROID_DATA":"/data",
            "MKSH":"/system/bin/sh",
            "HOME":"/data",
            "USER":"shell",
            "ANDROID_ROOT":"/system",
            "SHELL":"/system/bin/sh",
            "ANDROID_BOOTLOGO":"1",
            "TMPDIR":"/data/local/tmp",
            "ANDROID_ASSETS":"/system/app",
            "HOSTNAME":"bullhead",
            "EXTERNAL_STORAGE":"/sdcard",
            "ANDROID_STORAGE":"/storage",
        }
        env_ptrs = []
        for k in env:
            env_str = "%s=%s"%(k, env[k])
            env_ptr = sp_helpers.write_utf8(env_str)
            env_ptrs.append(env_ptr)
        #
        sp_helpers.commit()
        ptr_sz = self.emu.get_ptr_size()

        #auxv
        auxvs = {
            linux.AT_RANDOM:stack_guard_ptr,
            #TODO
        }
        auxv_base = sp_helpers.reserve(0x100)
        auxv_offset = auxv_base
        #print(hex(auxv_base).upper())
        for auxv_key in auxvs:
            #填充auvx数组
            auxv_val = auxvs[auxv_key]
            memory_helpers.write_ptrs_sz(self.emu.mu, auxv_offset, auxv_key, ptr_sz)
            memory_helpers.write_ptrs_sz(self.emu.mu, auxv_offset+ptr_sz, auxv_val, ptr_sz)
            auxv_offset+=2*ptr_sz
        #
        #auvx数组0结尾
        memory_helpers.write_ptrs_sz(self.emu.mu, auxv_offset, 0, 2*ptr_sz)

        env_base = sp_helpers.reserve(len(env_ptrs)+1)
        env_offset = env_base
        #envp
        for env_ptr in env_ptrs:
            memory_helpers.write_ptrs_sz(self.emu.mu, env_offset, env_ptr, ptr_sz)
            env_offset += ptr_sz
        #
        #0结尾
        memory_helpers.write_ptrs_sz(self.emu.mu, env_offset, 0, ptr_sz)

        nargc = len(argvs)
        argv_base = sp_helpers.reserve(nargc+1)
        argv_offset = argv_base
        #argv
        for argv_ptr in argvs_ptrs:
            memory_helpers.write_ptrs_sz(self.emu.mu, argv_offset, argv_ptr, ptr_sz)
            argv_offset += ptr_sz
        #
        #0结尾
        memory_helpers.write_ptrs_sz(self.emu.mu, argv_offset, 0, ptr_sz)
        
        #print(hex(kernel_args_base).upper())

        #KernelArgumentBlock
        #int argc;
        #char** argv;
        #char** envp;
        #Elf32_auxv_t* auxv;
        #abort_msg_t** abort_message_ptr;
        kernel_args_base = sp_helpers.reserve(5)
        memory_helpers.write_ptrs_sz(self.emu.mu, kernel_args_base, nargc, ptr_sz)
        memory_helpers.write_ptrs_sz(self.emu.mu, kernel_args_base+ptr_sz, argv_base, ptr_sz)
        memory_helpers.write_ptrs_sz(self.emu.mu, kernel_args_base+2*ptr_sz, env_base, ptr_sz)
        memory_helpers.write_ptrs_sz(self.emu.mu, kernel_args_base+3*ptr_sz, auxv_base, ptr_sz)
        memory_helpers.write_ptrs_sz(self.emu.mu, kernel_args_base+4*ptr_sz, 0, ptr_sz)


        #tls单独一个区域，不放在stack中
        self.emu.mu.mem_map(config.TLS_BASE, config.TLS_SIZE, UC_PROT_WRITE|UC_PROT_READ)
        tls_ptr = config.TLS_BASE
        mu = self.emu.mu
        #TLS_SLOT_SELF
        memory_helpers.write_ptrs_sz(mu, tls_ptr, tls_ptr, ptr_sz)
        #TLS_SLOT_THREAD_ID
        memory_helpers.write_ptrs_sz(mu, tls_ptr+ptr_sz, thread_internal_ptr, ptr_sz)
        #TLS_SLOT_ERRNO
        self.__errno_ptr = tls_ptr+2*ptr_sz
        #TLS_SLOT_BIONIC_PREINIT
        memory_helpers.write_ptrs_sz(mu, tls_ptr+3*ptr_sz, kernel_args_base, ptr_sz)
        arch = self.emu.get_arch()
        
        if (arch ==  emu_const.ARCH_ARM32):
            mu.reg_write(UC_ARM_REG_C13_C0_3, tls_ptr)
        else:
            mu.reg_write(UC_ARM64_REG_TPIDR_EL0, tls_ptr)

        sp_helpers.commit()
    #

    """
    :type emu androidemu.emulator.Emulator
    :type modules list[Module]
    """
    def __init__(self, emu, vfs_root):
        self.emu = emu
        self.modules = list()
        self.symbol_hooks = dict()
        self.counter_memory = config.BASE_ADDR
        self.__vfs_root = vfs_root
        soinfo_area_sz = 0x40000; 
        self.__soinfo_area_base = emu.memory.map(0, soinfo_area_sz, UC_PROT_WRITE | UC_PROT_READ)
        self.__errno_ptr = 0
        self.__tls_init()
    #

    def __get_ld_library_path(self):
        if (self.emu.get_arch() == emu_const.ARCH_ARM32):
            return ["/system/lib/"]
        else:
            return ["/system/lib64/"]
    #

    def find_so_on_disk(self, so_path):
        if os.path.isabs(so_path):
            path = misc_utils.vfs_path_to_system_path(self.__vfs_root, so_path)
            return path
        else:
            ld_library_path = self.__get_ld_library_path()
            so_name = so_path
            for lib_path in ld_library_path:
                lib_full_path = "%s/%s"%(lib_path, so_name)
                vfs_lib_path = misc_utils.vfs_path_to_system_path(self.__vfs_root, lib_full_path)
                if (os.path.exists(vfs_lib_path)):
                    return vfs_lib_path
                #
            #
        #
        return None
    #

    def add_symbol_hook(self, symbol_name, addr):
        self.symbol_hooks[symbol_name] = addr

    def find_symbol(self, addr):
        for module in self.modules:
            if addr in module.symbol_lookup:
                return module.symbol_lookup[addr]
        return None, None

    def find_symbol_str(self, symbol_str):
        for module in self.modules:
            sym = module.find_symbol(symbol_str)
            if sym is not None:
                return sym
        return None

    def find_module(self, addr):
        for module in self.modules:
            if module.base == addr:
                return module
        return None
    #

    def find_module_by_name(self, filename):
        absp1 = os.path.abspath(filename)
        for m in self.modules:
            absm = os.path.abspath(m.filename)
            if (absp1 == absm):
                return m
            #
        #
    #

    
    def mem_reserve(self, start, end):
        size_aligned = page_end(end) - page_start(start)
        ret = self.counter_memory
        self.counter_memory += size_aligned
        return ret
    #

    def load_module(self, filename, do_init=True):
        m = self.find_module_by_name(filename)
        if (m != None):
            return m
        #
        logger.debug("Loading module '%s'." % filename)
        #do sth like linker
        reader = elf_reader.ELFReader(filename)
        if (self.emu.get_arch() == emu_const.ARCH_ARM32 and not reader.is_elf32()):
            raise RuntimeError("arch is ARCH_ARM32 but so %s is not elf32!!!"%filename)
        elif self.emu.get_arch() == emu_const.ARCH_ARM64 and reader.is_elf32():
            raise RuntimeError("arch is ARCH_ARM64 but so %s is elf32!!!"%filename)
        #

        # Parse program header (Execution view).

        # - LOAD (determinate what parts of the ELF file get mapped into memory)
        load_segments = reader.get_load()

        # Find bounds of the load segments.
        bound_low = 0xFFFFFFFFFFFFFFFF
        bound_high = 0
        for segment in load_segments:
            p_memsz = segment["p_memsz"]
            if p_memsz == 0:
                continue
            p_vaddr = segment["p_vaddr"]
            if bound_low > p_vaddr:
                bound_low = p_vaddr
            high = p_vaddr + p_memsz

            if bound_high < high:
                bound_high = high
            #
        #

        '''
        // Segment addresses in memory.
        Elf32_Addr seg_start = phdr->p_vaddr + load_bias_;
        Elf32_Addr seg_end   = seg_start + phdr->p_memsz;

        Elf32_Addr seg_page_start = PAGE_START(seg_start);
        Elf32_Addr seg_page_end   = PAGE_END(seg_end);

        // File offsets.
        Elf32_Addr file_start = phdr->p_offset;
        Elf32_Addr file_end   = file_start + phdr->p_filesz;

        Elf32_Addr seg_file_end   = seg_start + phdr->p_filesz;
        Elf32_Addr file_page_start = PAGE_START(file_start);
        Elf32_Addr file_length = file_end - file_page_start;

        if (file_length != 0) {
        void* seg_addr = mmap((void*)seg_page_start,
                                file_length,
                                PFLAGS_TO_PROT(phdr->p_flags),
                                MAP_FIXED|MAP_PRIVATE,
                                fd_,
                                file_page_start);
        '''
        # Retrieve a base address for this module.
        load_base = self.mem_reserve(bound_low, bound_high)
        #所谓load_bias实际上就是load_base-第0个load 的vaddr, 多数情况下第0个load的vaddr为0，所以就是load_base,但是有些so 第0个load vaddr为非零，此时linker会议这个addr为起点装so，不是从0开始！！！
        #linker这么做的目的实际上是为了节省空间，举例：比如6.0 libc++.so 第0个load vaddr为0x9000,如果从0开始装，那么0到0x9000这段空间是浪费了点,所以linker装这个so会以0x9000开始装，0x9000相当于首地址0，so里面记载的所有内存的偏移都是基于0的，因此所有内存的偏移都要减去0x9000，
        #实际上linker的load_bias变量已经考虑这个问题，so在内存中所有偏移都基于load_bias就行
        load_bias = load_base - bound_low

        vf = VirtualFile(misc_utils.system_path_to_vfs_path(self.__vfs_root, filename), misc_utils.my_open(filename, os.O_RDONLY), filename)
        for segment in load_segments:
            p_flags = segment["p_flags"]
            prot = get_segment_protection(p_flags)
            prot = prot if prot != 0 else UC_PROT_ALL
            
            p_vaddr = segment["p_vaddr"]
            seg_start = load_bias + p_vaddr
            seg_page_start = page_start(seg_start)
            p_offset = segment["p_offset"]
            file_start = p_offset
            p_filesz = segment["p_filesz"]
            file_end = file_start + p_filesz
            file_page_start = page_start(file_start)
            file_length = file_end - file_page_start
            assert(file_length>0)
            if (file_length > 0):
                self.emu.memory.map(seg_page_start, file_length, prot, vf, file_page_start)
            #
            p_memsz = segment["p_memsz"]
            seg_end   = seg_start + p_memsz
            seg_page_end = page_end(seg_end)

            seg_file_end = seg_start+p_filesz

            seg_file_end = page_end(seg_file_end)
            '''
                    void* zeromap = mmap((void*)seg_file_end,
                        seg_page_end - seg_file_end,
                        PFLAGS_TO_PROT(phdr->p_flags),
                        MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE,
                        -1,
                        0);
            '''
            if (seg_page_end > seg_file_end):
                self.emu.memory.map(seg_file_end, seg_page_end-seg_file_end, prot)
        #

        # Find init array.
        init_array_addr, init_array_size = reader.get_init_array()
        init_array = []
        init_addr = reader.get_init()

        so_needed = reader.get_so_need()
        ld_library_path = self.__get_ld_library_path()
        for so_name in so_needed:
            path = self.find_so_on_disk(so_name)
            if (path is None):
                logger.warning("%s needed by %s do not exist in vfs %s"%(so_name, filename, self.__vfs_root))
                continue
            #
            libmod = self.load_module(path)
        #

        rels = reader.get_rels()
        symbols = reader.get_symbols()
        # Resolve all symbols.
        symbols_resolved = dict()

        for symbol in symbols:
            symbol_address = self._elf_get_symval(load_bias, symbol)
            if symbol_address is not None:
                name = symbol["name"]
                symbols_resolved[name] = symbol_address
            #
        #
        # Relocate.
        for rel_name in rels:
            rel_tbl = rels[rel_name]

            for rel in rel_tbl:
                r_info_sym = rel["r_info_sym"]
                sym = symbols[r_info_sym]
                sym_value = sym['st_value']

                rel_addr = load_bias + rel['r_offset']  # Location where relocation should happen
                rel_info_type = rel['r_info_type']

                #print(filename)
                #print("%x"%rel_addr)
                # Relocation table for ARM

                sym_name = reader.get_dyn_string_by_rel_sym(r_info_sym)
                if rel_info_type == arm.R_ARM_ABS32:
                    if sym_name in symbols_resolved:
                        sym_addr = symbols_resolved[sym_name]

                        value_orig_bytes = self.emu.mu.mem_read(rel_addr, 4)
                        value_orig = int.from_bytes(value_orig_bytes, byteorder='little')

                        #R_ARM_ABS32 how to relocate see android linker source code
                        #*reinterpret_cast<Elf32_Addr*>(reloc) += sym_addr;
                        value = sym_addr + value_orig
                        # Write the new value
                        #print(value)
                        self.emu.mu.mem_write(rel_addr, value.to_bytes(4, byteorder='little'))
                    #
                #
                elif (rel_info_type in (arm.R_AARCH64_ABS64, arm.R_AARCH64_ABS32)):
                    if sym_name in symbols_resolved:
                        #同arm32 只是地址变成8个字节
                        sym_addr = symbols_resolved[sym_name]

                        value_orig_bytes = self.emu.mu.mem_read(rel_addr, 8)
                        value_orig = int.from_bytes(value_orig_bytes, byteorder='little')
                        addend = rel["r_addend"]

                        value = sym_addr + value_orig + addend
                        # Write the new value
                        #print(value)
                        self.emu.mu.mem_write(rel_addr, value.to_bytes(8, byteorder='little'))
                    #
                #
                elif rel_info_type in (arm.R_ARM_GLOB_DAT, arm.R_ARM_JUMP_SLOT):
                    # Resolve the symbol.
                    #R_ARM_GLOB_DAT，R_ARM_JUMP_SLOT how to relocate see android linker source code
                    #*reinterpret_cast<Elf32_Addr*>(reloc) = sym_addr;
                    if sym_name in symbols_resolved:
                        value = symbols_resolved[sym_name]

                        # Write the new value
                        #print(value)
                        self.emu.mu.mem_write(rel_addr, value.to_bytes(4, byteorder='little'))
                    #
                #
                elif rel_info_type in (arm.R_AARCH64_GLOB_DAT, arm.R_AARCH64_JUMP_SLOT):
                    # Resolve the symbol.
                    #R_ARM_GLOB_DAT，R_ARM_JUMP_SLOT how to relocate see android linker source code
                    #*reinterpret_cast<Elf32_Addr*>(reloc) = sym_addr;
                    if sym_name in symbols_resolved:
                        value = symbols_resolved[sym_name]
                        addend = rel["r_addend"]
                        # Write the new value
                        #print(value)
                        self.emu.mu.mem_write(rel_addr, (value+addend).to_bytes(8, byteorder='little'))
                    #
                #
                elif rel_info_type in (arm.R_ARM_RELATIVE,):
                    if sym_value == 0:
                        # Load address at which it was linked originally.
                        value_orig_bytes = self.emu.mu.mem_read(rel_addr, 4)
                        value_orig = int.from_bytes(value_orig_bytes, byteorder='little')

                        # Create the new value
                        value = load_bias + value_orig

                        #print(value)
                        # Write the new value
                        self.emu.mu.mem_write(rel_addr, value.to_bytes(4, byteorder='little'))
                    else:
                        raise NotImplementedError() #impossible
                elif rel_info_type in (arm.R_AARCH64_RELATIVE,):
                    if sym_value == 0:
                        #这个重定位跟32的有所不同，32的是直接拿到rel_addr指向的数据作为修正，而这个直接使用addend作为修正
                        addend = rel["r_addend"]
                        # Create the new value
                        value = load_bias + addend

                        #print(value)
                        # Write the new value
                        self.emu.mu.mem_write(rel_addr, value.to_bytes(8, byteorder='little'))
                    else:
                        raise NotImplementedError() #impossible
                else:
                    logger.error("Unhandled relocation type %i." % rel_info_type)
                    raise NotImplementedError("Unhandled relocation type %i." % rel_info_type)
                #
            #
        #
        if (init_addr != 0):
            init_array.append(load_bias+init_addr)
        #
        init_item_sz = 4
        if (not reader.is_elf32()):
            init_item_sz = 8
        #
        for _ in range(int(init_array_size / init_item_sz)):
            b = self.emu.mu.mem_read(load_bias+init_array_addr, init_item_sz)
            fun_ptr = int.from_bytes(b, byteorder='little', signed = False)
            if (fun_ptr != 0):
                init_array.append(fun_ptr)
            #
            init_array_addr += init_item_sz
        #
        
        write_sz = reader.write_soinfo(self.emu.mu, load_base, load_bias, self.__soinfo_area_base)

        # Store information about loaded module.
        module = Module(filename, load_base, bound_high - bound_low, symbols_resolved, init_array, self.__soinfo_area_base)
        self.modules.append(module)
        
        self.__soinfo_area_base += write_sz
        if do_init:
            '''
            for r in self.emu.mu.mem_regions():
                print("region begin :0x%08X end:0x%08X, prot:%d"%(r[0], r[1], r[2]))
            #
            '''
            module.call_init(self.emu)
        #
        logger.info("finish load lib %s base 0x%08X"%(filename, load_base))
        return module
    #

    def _elf_get_symval(self, load_bias, symbol):
        name = symbol["name"]
        if name in self.symbol_hooks:
            return self.symbol_hooks[name]
        #
        if symbol['st_shndx'] == elf_reader.SHN_UNDEF:
            # External symbol, lookup value.
            target = self._elf_lookup_symbol(name)
            if target is None:
                # Extern symbol not found
                if symbol['st_info_bind'] == elf_reader.STB_WEAK:
                    # Weak symbol initialized as 0
                    return 0
                else:
                    logger.error('=> Undefined external symbol: %s' %name)
                    return None
            else:
                return target
        elif symbol['st_shndx'] == elf_reader.SHN_ABS:
            # Absolute symbol.
            return load_bias + symbol['st_value']
        else:
            # Internally defined symbol.
            return load_bias + symbol['st_value']
        #
    #

    def _elf_lookup_symbol(self, name):
        for module in self.modules:
            if name in module.symbols:
                addr = module.symbols[name]
                if addr != 0:
                    return addr
                #
            #
        #
        return None
    #

    def __iter__(self):
        for x in self.modules:
            yield x
        #
    #
