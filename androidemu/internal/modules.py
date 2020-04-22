import logging

from unicorn import UC_PROT_ALL

from . import arm
from ..utils.misc_utils import get_segment_protection,page_end, page_start
from .module import Module
from ..utils import memory_helpers,misc_utils
from ..vfs.virtual_file import VirtualFile
from .. import config
from . import elf_reader
import os

logger = logging.getLogger(__name__)


class Modules:
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
        with open(filename, 'rb') as fstream:
            #TODO: load elf without Section Header,pyelftools do not support.
            reader = elf_reader.ELFReader(fstream)

            # Parse program header (Execution view).

            # - LOAD (determinate what parts of the ELF file get mapped into memory)
            load_segments = reader.get_load()

            # Find bounds of the load segments.
            bound_low = 0
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

            vf = VirtualFile(misc_utils.system_path_to_vfs_path(self.__vfs_root, filename), misc_utils.my_open(filename, os.O_RDONLY), filename)
            for segment in load_segments:
                p_flags = segment["p_flags"]
                prot = get_segment_protection(p_flags)
                prot = prot if prot is not 0 else UC_PROT_ALL
                
                p_vaddr = segment["p_vaddr"]
                seg_start = load_base + p_vaddr
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
                self.emu.memory.map(seg_file_end, seg_page_end-seg_file_end, prot)
            #

            # Find init array.
            init_array_offset, init_array_size = reader.get_init_array()
            init_array = []
            init_offset = reader.get_init()

            so_needed = reader.get_so_need()
            for so_name in so_needed:
                path = misc_utils.vfs_path_to_system_path(self.__vfs_root, so_name)
                if (not os.path.exists(path)):
                    logger.warn("%s needed by %s do not exist in vfs %s"%(so_name, filename, self.__vfs_root))
                    continue
                #
                libmod = self.load_module(path)
            #

            rels = reader.get_rels()
            symbols = reader.get_symbols()
            # Resolve all symbols.
            symbols_resolved = dict()

            for symbol in symbols:
                symbol_address = self._elf_get_symval(load_base, symbol)
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

                    rel_addr = load_base + rel['r_offset']  # Location where relocation should happen
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
                    elif rel_info_type in (arm.R_ARM_GLOB_DAT, arm.R_ARM_JUMP_SLOT, 
                                                    arm.R_AARCH64_GLOB_DAT, arm.R_AARCH64_JUMP_SLOT):
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
                    elif rel_info_type in (arm.R_ARM_RELATIVE, arm.R_AARCH64_RELATIVE):
                        if sym_value == 0:
                            # Load address at which it was linked originally.
                            value_orig_bytes = self.emu.mu.mem_read(rel_addr, 4)
                            value_orig = int.from_bytes(value_orig_bytes, byteorder='little')

                            # Create the new value
                            value = load_base + value_orig

                            #print(value)
                            # Write the new value
                            self.emu.mu.mem_write(rel_addr, value.to_bytes(4, byteorder='little'))
                        else:
                            raise NotImplementedError()
                    else:
                        logger.error("Unhandled relocation type %i." % rel_info_type)
                    #
                #
            #
            if (init_offset != 0):
                init_array.append(load_base+init_offset)
            #
            for _ in range(int(init_array_size / 4)):
                b = self.emu.mu.mem_read(load_base+init_array_offset, 4)
                fun_ptr = int.from_bytes(b, byteorder='little', signed = False)
                if (fun_ptr != 0):
                    init_array.append(fun_ptr)
                #
                init_array_offset += 4
            #

            # Store information about loaded module.
            module = Module(filename, load_base, bound_high - bound_low, symbols_resolved, init_array)
            self.modules.append(module)
            #TODO init tls like linker
            '''
            void __libc_init_tls(KernelArgumentBlock& args) {
                __libc_auxv = args.auxv;
                unsigned stack_top = (__get_sp() & ~(PAGE_SIZE - 1)) + PAGE_SIZE;
                unsigned stack_size = 128 * 1024;
                unsigned stack_bottom = stack_top - stack_size;
                static void* tls[BIONIC_TLS_SLOTS];
                static pthread_internal_t thread;
                thread.tid = gettid();
                thread.tls = tls;
                pthread_attr_init(&thread.attr);
                pthread_attr_setstack(&thread.attr, (void*) stack_bottom, stack_size);
                _init_thread(&thread, false);
                __init_tls(&thread);
                tls[TLS_SLOT_BIONIC_PREINIT] = &args;
            }
            '''
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

    def _elf_get_symval(self, elf_base, symbol):
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
            return elf_base + symbol['st_value']
        else:
            # Internally defined symbol.
            return elf_base + symbol['st_value']
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

    def __iter__(self):
        for x in self.modules:
            yield x
