import struct
import os
import sys

from ..utils import memory_helpers,misc_utils

PT_NULL   = 0
PT_LOAD   = 1
PT_DYNAMIC =2
PT_INTERP  =3
PT_NOTE    =4
PT_SHLIB   =5
PT_PHDR    =6


DT_NULL	=0
DT_NEEDED	=1
DT_PLTRELSZ	=2
DT_PLTGOT	=3
DT_HASH		=4
DT_STRTAB	=5
DT_SYMTAB	=6
DT_RELA		=7
DT_RELASZ	=8
DT_RELAENT	=9
DT_STRSZ	=10
DT_SYMENT	=11
DT_INIT =0x0c
DT_INIT_ARRAY =0x19
DT_FINI_ARRAY =0x1a
DT_INIT_ARRAYSZ =0x1b
DT_FINI_ARRAYSZ =0x1c
DT_SONAME	=14
DT_RPATH 	=15
DT_SYMBOLIC	=16
DT_REL	    =17
DT_RELSZ	=18
DT_RELENT	=19
DT_PLTREL	=20
DT_DEBUG	=21
DT_TEXTREL	=22
DT_JMPREL	=23
DT_GNU_HASH = 0x6ffffef5
DT_LOPROC	=0x70000000
DT_HIPROC	=0x7fffffff

SHN_UNDEF	=0
SHN_LORESERVE	=0xff00
SHN_LOPROC	=0xff00
SHN_HIPROC	=0xff1f
SHN_ABS	=0xfff1
SHN_COMMON	=0xfff2
SHN_HIRESERVE	=0xffff
SHN_MIPS_ACCOMON	=0xff00

STB_LOCAL = 0
STB_GLOBAL =1
STB_WEAK   =2
STT_NOTYPE  =0
STT_OBJECT  =1
STT_FUNC    =2
STT_SECTION =3
STT_FILE    =4

class ELFReader:
    '''
    #define EI_NIDENT	16
    typedef struct elf32_hdr{
        unsigned char	e_ident[EI_NIDENT];
        Elf32_Half	e_type;
        Elf32_Half	e_machine;
        Elf32_Word	e_version;
        Elf32_Addr	e_entry;  /* Entry point */
        Elf32_Off	e_phoff;
        Elf32_Off	e_shoff;
        Elf32_Word	e_flags;
        Elf32_Half	e_ehsize;
        Elf32_Half	e_phentsize;
        Elf32_Half	e_phnum;
        Elf32_Half	e_shentsize;
        Elf32_Half	e_shnum;
        Elf32_Half	e_shstrndx;
    } Elf32_Ehdr;

    typedef struct elf32_phdr{
        Elf32_Word	p_type;
        Elf32_Off	p_offset;
        Elf32_Addr	p_vaddr;
        Elf32_Addr	p_paddr;
        Elf32_Word	p_filesz;
        Elf32_Word	p_memsz;
        Elf32_Word	p_flags;
        Elf32_Word	p_align;
    } Elf32_Phdr;

    typedef struct elf32_sym{
        Elf32_Word	st_name;
        Elf32_Addr	st_value;
        Elf32_Word	st_size;
        unsigned char	st_info;
        unsigned char	st_other;
        Elf32_Half	st_shndx;
        } Elf32_Sym;
    typedef struct elf32_rel {
        Elf32_Addr	r_offset;
        Elf32_Word	r_info;
    } Elf32_Rel;
    typedef struct elf64_rela{
        Elf64_Addr r_offset;	/* Location at which to apply the action */
        Elf64_Xword r_info;	/* index and type of relocation */
        Elf64_Sxword r_addend;	/* Constant addend used to compute value */
    } Elf64_Rela;
    '''
    @staticmethod
    def __elf32_r_sym(x):
        return x>>8
    #
    @staticmethod
    def __elf32_r_type(x):
        return x & 0xff
    #


    @staticmethod
    def __elf64_r_sym(x):
        return x>>32
    #
    @staticmethod
    def __elf64_r_type(x):
        return x & 0xffffffff
    #


#define ELF_ST_BIND(x)	((x) >> 4)
#define ELF_ST_TYPE(x)	(((unsigned int) x) & 0xf)
    @staticmethod
    def __elf_st_bind(x):
        return x >> 4
    #

    @staticmethod
    def __elf_st_type(x):
        return x & 0xf
    #

    @staticmethod
    def check_elf32(filename):
        with open(filename, "rb") as f:
            f.seek(0x4, os.SEEK_SET)
            buf = f.read(1)
            return buf[0] == 1
        #
    #
    def __st_name_to_name(self, st_name):
        assert st_name < self.__dyn_str_sz, "__st_name_to_name st_name %d out of range %d"%(st_name, self.__dyn_str_sz)
        endId=self.__dyn_str_buf.find(b"\x00", st_name)
        r = self.__dyn_str_buf[st_name:endId]
        name = r.decode("utf-8")
        return name
    #

    def __init__(self, filename):

        with open(filename, 'rb') as f:
            is_elf32 = ELFReader.check_elf32(filename)
            self.__is_elf32 = is_elf32
            elf_r_sym = ELFReader.__elf32_r_sym
            elf_r_type = ELFReader.__elf32_r_type

            ehdr_sz = 52
            phdr_sz = 32
            elf_dyn_sz = 8
            elf_sym_sz = 16
            elf_rel_sz = 8
            edhr_pattern = "<16sHHIIIIIHHHHHH"
            phdr_pattern = "<IIIIIIII"
            dyn_pattern = "<II"
            sym_pattern = "<IIIccH"
            rel_pattern = "<II"
            
            if (not is_elf32):
                #elf64
                ehdr_sz = 64
                phdr_sz = 56
                elf_dyn_sz = 16
                elf_sym_sz = 24
                #实际上是rela
                elf_rel_sz = 24
                elf_r_sym = ELFReader.__elf64_r_sym
                elf_r_type = ELFReader.__elf64_r_type
                edhr_pattern = "<16sHHIQQQIHHHHHH"
                phdr_pattern = "<IIQQQQQQ"
                dyn_pattern = "<QQ"
                sym_pattern = "<IccHQQ"
                rel_pattern = "<QQq"
            #

            self.__filename = filename
            self.__init_array_addr = 0
            self.__init_array_size = 0
            self.__init_addr = 0
            self.__nbucket = 0
            self.__nchain = 0
            self.__bucket_addr = 0
            self.__chain_addr = 0


            self.__phdrs = []
            self.__loads = []
            self.__dynsymols = []
            self.__rels = {}
            self.__file = f
            ehdr_bytes = f.read(ehdr_sz)
            _, _ , _, _, _, phoff, _, _, _, _, phdr_num, _, _, _ = struct.unpack(edhr_pattern, ehdr_bytes)

            #print(phoff)
            #__phdroff same as phdraddr
            self.__phoff = phoff
            self.__phdr_num = phdr_num
            f.seek(phoff, 0)

            dyn_off = 0
            dyn_addr = 0
            self.__sz = 0
            for i in range(0, phdr_num):
                phdr_bytes = f.read(phdr_sz)
                #32与64的phdr结构体顺序有区别
                if (is_elf32):
                    p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack(phdr_pattern, phdr_bytes)
                else:   #64
                    p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack(phdr_pattern, phdr_bytes)
                #

                phdr = {"p_type":p_type, "p_offset":p_offset, "p_vaddr":p_vaddr, "p_paddr":p_paddr, \
                                                "p_filesz":p_filesz, "p_memsz":p_memsz, "p_flags":p_flags, "p_align":p_align}
                self.__phdrs.append(phdr)
                if (p_type == PT_DYNAMIC):
                    dyn_off = p_offset
                    dyn_addr = p_vaddr
                #
                elif(p_type == PT_LOAD):
                    self.__loads.append(phdr)
                #
                self.__sz += p_memsz
            #
            
            assert dyn_off > 0, "error no dynamic in this elf."
            self.__dyn_addr = dyn_addr
            f.seek(dyn_off, 0)
            dyn_str_addr = 0
            dyn_str_sz = 0
            self.__dyn_str_buf = b""
            dyn_sym_addr = 0
            nsymbol = -1
            rel_addr = 0
            rel_count = 0
            relplt_addr = 0
            relplt_count = 0
            dt_needed = []

            #解析dynamiic的时候,里面所有偏移都是相对于第0个load 的p_vaddr,所以要得出在文件中的偏移，需要统一减去self.__loads[0]["p_vaddr"]
            bias = self.__loads[0]["p_vaddr"] - self.__loads[0]["p_offset"]
            while True:
                dyn_item_bytes = f.read(elf_dyn_sz)
                d_tag, d_val_ptr = struct.unpack(dyn_pattern, dyn_item_bytes)
                #print(d_tag)
                if (d_tag == DT_NULL):
                    break
                if (d_tag == DT_RELA):
                    #根据linker源码 rela只出现在arm64中
                    assert is_elf32 == False, "get DT_RELA when parsing elf64 impossible in android!!!"
                    rel_addr = d_val_ptr
                elif (d_tag == DT_RELASZ):
                    rel_count = int(d_val_ptr / elf_rel_sz)
                #
                elif (d_tag == DT_REL):
                    #rel只出现在arm中
                    assert is_elf32 == True, "get DT_REL when parsing elf32 impossible in android!!!"
                    rel_addr = d_val_ptr
                #
                elif (d_tag == DT_RELSZ):
                    rel_count = int(d_val_ptr / elf_rel_sz)
                #
                elif (d_tag == DT_JMPREL):
                    relplt_addr = d_val_ptr
                #
                elif(d_tag == DT_PLTRELSZ):
                    relplt_count = int(d_val_ptr / elf_rel_sz)
                #
                elif (d_tag == DT_SYMTAB):
                    dyn_sym_addr = d_val_ptr
                #
                elif(d_tag == DT_STRTAB):
                    dyn_str_addr = d_val_ptr
                #
                elif(d_tag == DT_STRSZ):
                    dyn_str_sz = d_val_ptr
                #
                elif(d_tag == DT_HASH):
                    '''
                    nbucket_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[0];
                    nchain_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[1];
                    bucket_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr + 8);
                    chain_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr + 8 + nbucket_ * 4);
                    '''
                    n = f.tell()
                    f.seek(d_val_ptr-bias, 0)
                    hash_heads = f.read(8)
                    f.seek(n, 0)
                    self.__nbucket, self.__nchain = struct.unpack("<II", hash_heads)
                    self.__bucket_addr = d_val_ptr + 8
                    self.__chain_addr = d_val_ptr + 8 + self.__nbucket * 4
                    nsymbol = self.__nchain
                #
                elif(d_tag == DT_GNU_HASH):
                    '''
                    struct gnu_hash_table {
                        uint32_t nbuckets;
                        uint32_t symoffset;
                        uint32_t bloom_size;
                        uint32_t bloom_shift;
                        uint32_t bloom[bloom_size]; /* uint32_t for 32-bit binaries */
                        //uint64_t bloom[bloom_size]; /* uint64_t in 64-bit */

                        uint32_t buckets[nbuckets];
                        uint32_t chain[];
                    };
                    '''
                    #参考https://flapenguin.me/elf-dt-gnu-hash
                    ori = f.tell()
                    f.seek(d_val_ptr - bias, 0)
                    hash_heads = f.read(16)
                    f.seek(ori, 0)
                    gnu_nbucket_, symoffset, gnu_maskwords_, gnu_shift2_ = struct.unpack("<IIII", hash_heads)
                    gnu_bloom_filter_ = d_val_ptr - bias + 16
                    if (is_elf32):
                        gnu_bucket_ = gnu_bloom_filter_ + 4*gnu_maskwords_
                    else:
                        gnu_bucket_ = gnu_bloom_filter_ + 8*gnu_maskwords_
                    #
                    gnu_chain_ = gnu_bucket_ + 4*gnu_nbucket_ - 4*symoffset

                    #遍历bucket列表，找最大的symbolid
                    #注意，最大的symbolid不一定就是最后一个bucket,6.0的libart.so就是例外
                    #获取符号数量的正确方式参考https://flapenguin.me/elf-dt-gnu-hash
                    maxbucket_symidx = 0
                    for bucket_id in range(0, gnu_nbucket_):
                        f.seek(gnu_bucket_+4*bucket_id, 0)
                        nbytes = f.read(4)
                        symidx = int.from_bytes(nbytes, 'little')
                        if (symidx > maxbucket_symidx):
                            maxbucket_symidx = symidx
                        #
                    #
                    #实际上bucket存的是chain里面第一个symbolId
                    #沿着bucket找到最大的symid，并不是最大的id，最大的id需要从这个id开始
                    #在chain里面继续顺序找下去，直到chain结束，就是symbol的个数
                    max_symid = maxbucket_symidx
                    while True:
                        #从bucket里找到的最大symid开始遍历,找到chain结尾就是符号数量
                        f.seek(gnu_chain_+4*max_symid, 0)
                        cbytes = f.read(4)
                        c = int.from_bytes(cbytes, 'little')
                        #Chain ends with an element with the lowest bit set to 1.
                        if ((c & 1) == 1):
                            break
                        #
                        max_symid = max_symid + 1
                    #
                    nsymbol = max_symid + 1
                    f.seek(ori, 0)
                #
                elif (d_tag == DT_INIT):
                    self.__init_addr = d_val_ptr
                elif(d_tag == DT_INIT_ARRAY):
                    self.__init_array_addr = d_val_ptr
                elif(d_tag == DT_INIT_ARRAYSZ):
                    self.__init_array_size = d_val_ptr
                #
                elif (d_tag == DT_NEEDED):
                    dt_needed.append(d_val_ptr)
                #
                elif (d_tag == DT_PLTGOT):
                    self.__plt_got_addr = d_val_ptr
                #
            #
            assert nsymbol > -1, "can not detect nsymbol by DT_HASH or DT_GNU_HASH, make sure their exist in so!!!"
            self.__dyn_str_addr = dyn_str_addr
            self.__dyn_str_addr = dyn_sym_addr

            self.__dyn_str_sz = dyn_str_sz

            self.__pltrel_addr = relplt_addr
            self.__pltrel_count = relplt_count

            self.__rel_addr = rel_addr
            self.__rel_count = rel_count

            f.seek(dyn_str_addr - bias)
            self.__dyn_str_buf = f.read(dyn_str_sz)
            
            f.seek(dyn_sym_addr - bias, 0)
            for i in range(0, nsymbol):
                sym_bytes = f.read(elf_sym_sz)
                if (is_elf32):
                    st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack(sym_pattern, sym_bytes)
                else:
                    #64排布有改变
                    st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack(sym_pattern, sym_bytes)
                #
                int_st_info = int.from_bytes(st_info, byteorder='little', signed = False)
                st_info_bind = ELFReader.__elf_st_bind(int_st_info)
                st_info_type = ELFReader.__elf_st_type(int_st_info)
                name = ""
                try:
                    name = self.__st_name_to_name(st_name)
                except UnicodeDecodeError as e:
                    print("warning can not decode sym index %d at off 0x%08x skip"%(i, st_name))
                #
                d = {"name":name, "st_name":st_name, "st_value":st_value, "st_size":st_size, "st_info":st_info, "st_other":st_other, 
                "st_shndx":st_shndx, "st_info_bind":st_info_bind, "st_info_type":st_info_type}
                self.__dynsymols.append(d)
            #
            rel_table = []
            if (rel_count > 0):
                #rel不一定有
                f.seek(rel_addr - bias, 0)

                for i in range(0, rel_count):
                    rel_item_bytes = f.read(elf_rel_sz)
                    d = {}
                    if (is_elf32):
                        r_offset, r_info = struct.unpack(rel_pattern, rel_item_bytes)
                    else:
                        #64 rela
                        r_offset, r_info, r_addend = struct.unpack(rel_pattern, rel_item_bytes)
                    #
                    r_info_sym = elf_r_sym(r_info)
                    r_info_type = elf_r_type(r_info)
                    d = {"r_offset":r_offset, "r_info":r_info, "r_info_type":r_info_type, "r_info_sym":r_info_sym}
                    if (not is_elf32):
                        d["r_addend"] = r_addend
                    rel_table.append(d)
                #
            #
            self.__rels["dynrel"] = rel_table
            #print(self.__rels["dynrel"])
            relplt_table = []
            if (relplt_count > 0):
                f.seek(relplt_addr - bias, 0)
                for i in range(0, relplt_count):
                    rel_item_bytes = f.read(elf_rel_sz)
                    if (is_elf32):
                        r_offset, r_info = struct.unpack(rel_pattern, rel_item_bytes)
                    else:
                        #64 rela
                        r_offset, r_info, r_addend = struct.unpack(rel_pattern, rel_item_bytes)
                    #
                    r_info_sym = elf_r_sym(r_info)
                    r_info_type = elf_r_type(r_info)
                    d = {"r_offset":r_offset, "r_info":r_info, "r_info_type":r_info_type, "r_info_sym":r_info_sym}
                    #rela多了一个字段
                    if (not is_elf32):
                        d["r_addend"] = r_addend
                    relplt_table.append(d)
                #
                self.__rels["relplt"] = relplt_table
                self.__so_needed = []
                for str_off in dt_needed:
                    #这里存的是相对于字符串表里面的偏移，因此不需要-bias，字符串表地址搞对就行
                    endId=self.__dyn_str_buf.find(b"\x00", str_off)
                    so_name = self.__dyn_str_buf[str_off:endId]
                    self.__so_needed.append(so_name.decode("utf-8"))
                #
            #
        #
    #

    def get_load(self):
        return self.__loads
    #

    def get_symbols(self):
        return self.__dynsymols
    #

    def get_rels(self):
        return self.__rels
    #

    def is_elf32(self):
        return self.__is_elf32
    #

    def get_dyn_string_by_rel_sym(self, rel_sym):
        nsym = len(self.__dynsymols)
        assert rel_sym < nsym
        sym =  self.__dynsymols[rel_sym]
        st_name = sym["st_name"]
        r = self.__st_name_to_name(st_name)
        return r
    #

    def get_init_array(self):
        return self.__init_array_addr, self.__init_array_size
    #

    def get_init(self):
        return self.__init_addr
    #

    def get_so_need(self):
        return self.__so_needed
    #

    #android 4.4.4 soinfo
    '''
    struct link_map_t {
        uintptr_t l_addr;
        char*  l_name;
        uintptr_t l_ld;
        link_map_t* l_next;
        link_map_t* l_prev;
    };

    #define SOINFO_NAME_LEN 128
    struct soinfo {
    public:
        char name[SOINFO_NAME_LEN];
        const Elf32_Phdr* phdr;
        size_t phnum;
        Elf32_Addr entry;
        Elf32_Addr base;
        unsigned size;
        uint32_t unused1;  // DO NOT USE, maintained for compatibility.
        Elf32_Dyn* dynamic;
        uint32_t unused2; // DO NOT USE, maintained for compatibility
        uint32_t unused3; // DO NOT USE, maintained for compatibility
        soinfo* next;
        unsigned flags;
        const char* strtab;
        Elf32_Sym* symtab;
        size_t nbucket;
        size_t nchain;
        unsigned* bucket;
        unsigned* chain;
        unsigned* plt_got;
        Elf32_Rel* plt_rel;
        size_t plt_rel_count;
        Elf32_Rel* rel;
        size_t rel_count;
        linker_function_t* preinit_array;
        size_t preinit_array_count;
        linker_function_t* init_array;
        size_t init_array_count;
        linker_function_t* fini_array;
        size_t fini_array_count;
        linker_function_t init_func;
        linker_function_t fini_func;
        
        // ARM EABI section used for stack unwinding.
        unsigned* ARM_exidx;
        size_t ARM_exidx_count;
        
        size_t ref_count;
        link_map_t link_map;
        bool constructors_called;
        // When you read a virtual address from the ELF file, add this
        // value to get the corresponding address in the process' address space.
        Elf32_Addr load_bias;
    };
    '''
    def __write_soinfo32(self, mu, load_base, load_bias, info_base):

        #在虚拟机中构造一个soinfo结构
        assert len(self.__filename)<128
        
        #name
        memory_helpers.write_utf8(mu, info_base+0, self.__filename)
        #phdr
        mu.mem_write(info_base+128, int(load_base+self.__phoff).to_bytes(4, byteorder='little'))
        #phnum
        mu.mem_write(info_base+132, int(self.__phdr_num).to_bytes(4, byteorder='little'))
        #entry
        mu.mem_write(info_base+136, int(0).to_bytes(4, byteorder='little'))
        #base
        mu.mem_write(info_base+140, int(load_base).to_bytes(4, byteorder='little'))
        #size
        mu.mem_write(info_base+144, int(self.__sz).to_bytes(4, byteorder='little'))
        #unused1
        mu.mem_write(info_base+148, int(0).to_bytes(4, byteorder='little'))
        #dynamic
        mu.mem_write(info_base+152, int(load_base+self.__dyn_addr).to_bytes(4, byteorder='little'))
        #unused2
        mu.mem_write(info_base+156, int(0).to_bytes(4, byteorder='little'))
        #unused3
        mu.mem_write(info_base+160, int(0).to_bytes(4, byteorder='little'))
        #next
        mu.mem_write(info_base+164, int(0).to_bytes(4, byteorder='little'))
        #flags
        mu.mem_write(info_base+168, int(0).to_bytes(4, byteorder='little'))
        #strtab
        mu.mem_write(info_base+172, int(load_base+self.__dyn_str_addr).to_bytes(4, byteorder='little'))
        #symtab    
        mu.mem_write(info_base+176, int(load_base+self.__dyn_str_addr).to_bytes(4, byteorder='little'))
        #nbucket
        mu.mem_write(info_base+180, int(self.__nbucket).to_bytes(4, byteorder='little'))
        #nchain
        mu.mem_write(info_base+184, int(self.__nchain).to_bytes(4, byteorder='little'))

        #bucket
        mu.mem_write(info_base+188, int(load_base+self.__bucket_addr).to_bytes(4, byteorder='little'))
        #nchain
        mu.mem_write(info_base+192, int(load_base+self.__chain_addr).to_bytes(4, byteorder='little'))

        #plt_got
        mu.mem_write(info_base+196, int(load_base+self.__plt_got_addr).to_bytes(4, byteorder='little'))

        #plt_rel
        mu.mem_write(info_base+200, int(load_base+self.__pltrel_addr).to_bytes(4, byteorder='little'))
        #plt_rel_count
        mu.mem_write(info_base+204, int(self.__pltrel_count).to_bytes(4, byteorder='little'))

        #rel
        mu.mem_write(info_base+208, int(load_base+self.__rel_addr).to_bytes(4, byteorder='little'))
        #rel_count
        mu.mem_write(info_base+212, int(self.__rel_count).to_bytes(4, byteorder='little'))

        #preinit_array
        mu.mem_write(info_base+216, int(0).to_bytes(4, byteorder='little'))
        #preinit_array_count
        mu.mem_write(info_base+220, int(0).to_bytes(4, byteorder='little'))

        #init_array
        mu.mem_write(info_base+224, int(load_base+self.__init_array_addr).to_bytes(4, byteorder='little'))
        #init_array_count
        mu.mem_write(info_base+228, int(self.__init_array_size/4).to_bytes(4, byteorder='little'))

        #finit_array
        mu.mem_write(info_base+232, int(0).to_bytes(4, byteorder='little'))
        #finit_array_count
        mu.mem_write(info_base+236, int(0).to_bytes(4, byteorder='little'))

        #init_func
        mu.mem_write(info_base+240, int(load_base+self.__init_addr).to_bytes(4, byteorder='little'))
        #fini_func
        mu.mem_write(info_base+244, int(0).to_bytes(4, byteorder='little'))

        #ARM_exidx
        mu.mem_write(info_base+248, int(0).to_bytes(4, byteorder='little'))
        #ARM_exidx_count
        mu.mem_write(info_base+252, int(0).to_bytes(4, byteorder='little'))

        #ref_count
        mu.mem_write(info_base+256, int(1).to_bytes(4, byteorder='little'))

        #link_map
        mu.mem_write(info_base+260, int(0).to_bytes(20, byteorder='little'))

        #constructors_called
        mu.mem_write(info_base+280, int(1).to_bytes(4, byteorder='little'))
        
        #Elf32_Addr load_bias
        load_bias = load_base - (self.__loads[0]["p_vaddr"] - self.__loads[0]["p_offset"])
        mu.mem_write(info_base+284, int(load_bias).to_bytes(4, byteorder='little'))
        
        soinfo_sz = 288
        return soinfo_sz
    #

    def __write_soinfo64(self, mu, load_base, load_bias, info_base):
        #在虚拟机中构造一个soinfo结构
        assert len(self.__filename)<128
        
        #name
        memory_helpers.write_utf8(mu, info_base+0, self.__filename)
        off = 128
        #phdr
        mu.mem_write(info_base+off, int(load_base+self.__phoff).to_bytes(8, byteorder='little'))
        off += 8
        #phnum
        mu.mem_write(info_base+off, int(self.__phdr_num).to_bytes(8, byteorder='little'))
        off += 8

        #entry
        mu.mem_write(info_base+off, int(0).to_bytes(8, byteorder='little'))
        off += 8

        #base
        mu.mem_write(info_base+off, int(load_base).to_bytes(8, byteorder='little'))
        off += 8

        #size
        mu.mem_write(info_base+off, int(self.__sz).to_bytes(8, byteorder='little'))
        off += 8

        #unused1
        mu.mem_write(info_base+off, int(0).to_bytes(8, byteorder='little')) #unsed uint32  占用8因为内存对齐
        off += 8

        #dynamic
        mu.mem_write(info_base+off, int(load_base+self.__dyn_addr).to_bytes(8, byteorder='little'))
        off += 8

        #unused2
        mu.mem_write(info_base+off, int(0).to_bytes(4, byteorder='little'))
        off += 4
        #unused3
        mu.mem_write(info_base+off, int(0).to_bytes(4, byteorder='little'))
        off += 4
        #next
        mu.mem_write(info_base+off, int(0).to_bytes(8, byteorder='little'))
        off += 8
        #flags
        mu.mem_write(info_base+off, int(0).to_bytes(8, byteorder='little')) #内存对齐
        off += 8

        #strtab
        mu.mem_write(info_base+off, int(load_base+self.__dyn_str_addr).to_bytes(8, byteorder='little'))
        off += 8

        #symtab    
        mu.mem_write(info_base+off, int(load_base+self.__dyn_str_addr).to_bytes(8, byteorder='little'))
        off += 8

        #nbucket
        mu.mem_write(info_base+off, int(self.__nbucket).to_bytes(4, byteorder='little'))
        off += 8
        #nchain
        mu.mem_write(info_base+off, int(self.__nchain).to_bytes(4, byteorder='little'))
        off += 8

        #bucket
        mu.mem_write(info_base+off, int(load_base+self.__bucket_addr).to_bytes(4, byteorder='little'))
        off += 8
        #nchain
        mu.mem_write(info_base+off, int(load_base+self.__chain_addr).to_bytes(4, byteorder='little'))
        off += 8

        #plt_rela
        mu.mem_write(info_base+off, int(load_base+self.__pltrel_addr).to_bytes(8, byteorder='little'))
        off += 8
        #plt_rela_count
        mu.mem_write(info_base+off, int(self.__pltrel_count).to_bytes(8, byteorder='little'))
        off += 8

        #rela
        mu.mem_write(info_base+off, int(load_base+self.__rel_addr).to_bytes(8, byteorder='little'))
        off += 8
        
        #rela_count
        mu.mem_write(info_base+off, int(self.__rel_count).to_bytes(8, byteorder='little'))
        off += 8

        #preinit_array
        mu.mem_write(info_base+off, int(0).to_bytes(8, byteorder='little'))
        off += 8
        #preinit_array_count
        mu.mem_write(info_base+off, int(0).to_bytes(8, byteorder='little'))
        off += 8

        #init_array
        mu.mem_write(info_base+off, int(load_base+self.__init_array_addr).to_bytes(8, byteorder='little'))
        off += 8
        #init_array_count
        mu.mem_write(info_base+off, int(self.__init_array_size/8).to_bytes(8, byteorder='little'))
        off += 8

        #finit_array
        mu.mem_write(info_base+off, int(0).to_bytes(8, byteorder='little'))
        off += 8
        #finit_array_count
        mu.mem_write(info_base+off, int(0).to_bytes(8, byteorder='little'))
        off += 8

        #init_func
        mu.mem_write(info_base+off, int(load_base+self.__init_addr).to_bytes(8, byteorder='little'))
        off += 8
        #fini_func
        mu.mem_write(info_base+off, int(0).to_bytes(8, byteorder='little'))
        off += 8

        #ARM_exidx
        mu.mem_write(info_base+off, int(0).to_bytes(8, byteorder='little'))
        off += 8
        #ARM_exidx_count
        mu.mem_write(info_base+off, int(0).to_bytes(8, byteorder='little'))
        off += 8

        #ref_count
        mu.mem_write(info_base+off, int(1).to_bytes(4, byteorder='little'))
        off += 8

        #link_map
        mu.mem_write(info_base+off, int(0).to_bytes(40, byteorder='little'))
        off += 40

        #constructors_called
        mu.mem_write(info_base+off, int(1).to_bytes(8, byteorder='little'))
        off += 8
        
        #Elf64_Addr load_bias
        mu.mem_write(info_base+off, int(load_bias).to_bytes(8, byteorder='little'))
        off += 8

        #has_DT_SYMBOLIC
        mu.mem_write(info_base+off, int(0).to_bytes(8, byteorder='little'))
        off += 8

        soinfo_sz = off
        return soinfo_sz
    #

    def write_soinfo(self, mu, load_base, load_bias, info_base):
        if (self.is_elf32()):
            return self.__write_soinfo32(mu, load_base, load_bias, info_base)
        #
        else:
            return self.__write_soinfo64(mu, load_base, load_bias, info_base)
        #
    #

#