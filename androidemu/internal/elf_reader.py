import struct
import os
import sys

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

    def __st_name_to_name(self, st_name):
        assert st_name < self.__dyn_str_sz, "__st_name_to_name st_name %d out of range %d"%(st_name, self.__dyn_str_sz)
        endId=self.__dyn_str_buf.find(b"\x00", st_name)
        r = self.__dyn_str_buf[st_name:endId]
        return r.decode("utf-8")
    #

    def __init__(self, f):
        ehdr32_sz = 52
        phdr32_sz = 32
        elf32_dyn_sz = 8
        elf32_sym_sz = 16
        elf32_rel_sz = 8

        self.__init_array_off = 0
        self.__init_array_size = 0
        self.__init_off = 0

        self.__phdrs = []
        self.__loads = []
        self.__dynsymols = []
        self.__rels = {}
        self.__file = f
        ehdr_bytes = f.read(ehdr32_sz)
        _, _ , _, _, _, phoff, _, _, _, _, phdr_num, _, _, _ = struct.unpack("<16sHHIIIIIHHHHHH", ehdr_bytes)

        #print(phoff)
        f.seek(phoff, 0)

        dyn_off = 0
        for i in range(0, phdr_num):
            phdr_bytes = f.read(phdr32_sz)
            p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack("<IIIIIIII", phdr_bytes)
            phdr = {"p_type":p_type, "p_offset":p_offset, "p_vaddr":p_vaddr, "p_paddr":p_paddr, \
                                            "p_filesz":p_filesz, "p_memsz":p_memsz, "p_flags":p_flags, "p_align":p_align}
            self.__phdrs.append(phdr)
            if (p_type == PT_DYNAMIC):
                dyn_off = p_offset
            #
            elif(p_type == PT_LOAD):
                self.__loads.append(phdr)
            #
        #
        assert dyn_off > 0, "error no dynamic for this elf."
        f.seek(dyn_off, 0)
        dyn_str_off = 0
        dyn_str_sz = 0
        self.__dyn_str_buf = b""
        dyn_sym_off = -0
        nsymbol = -1
        rel_off = 0
        rel_count = 0
        relplt_off = 0
        relplt_count = 0
        dt_needed = []
        while True:
            dyn_item_bytes = f.read(elf32_dyn_sz)
            d_tag, d_val_ptr = struct.unpack("<II", dyn_item_bytes)
            if (d_tag == DT_NULL):
                break
            if (d_tag == DT_RELA):
                assert False, "64bit not support now"
            elif (d_tag == DT_REL):
                rel_off = d_val_ptr
            #
            elif (d_tag == DT_RELSZ):
                rel_count = int(d_val_ptr / elf32_rel_sz)
            #
            elif (d_tag == DT_JMPREL):
                relplt_off = d_val_ptr
            #
            elif(d_tag == DT_PLTRELSZ):
                relplt_count = int(d_val_ptr / elf32_rel_sz)
            #
            elif (d_tag == DT_SYMTAB):
                dyn_sym_off = d_val_ptr
            #
            elif(d_tag == DT_STRTAB):
                dyn_str_off = d_val_ptr
            #
            elif(d_tag == DT_STRSZ):
                dyn_str_sz = d_val_ptr
            #
            elif(d_tag == DT_HASH):
                '''
                memcpy(&nbucket, buffer + g_shdr[HASH].sh_offset, 4);
				memcpy(&nchain, buffer + g_shdr[HASH].sh_offset + 4, 4)
                '''
                n = f.tell()
                f.seek(d_val_ptr, 0)
                hash_heads = f.read(8)
                f.seek(n, 0)
                nbucket, nchain = struct.unpack("<II", hash_heads)
                nsymbol = nchain
            #
            elif (d_tag == DT_INIT):
                self.__init_off = d_val_ptr
            elif(d_tag == DT_INIT_ARRAY):
                self.__init_array_off = d_val_ptr
            elif(d_tag == DT_INIT_ARRAYSZ):
                self.__init_array_size = d_val_ptr
            #
            elif (d_tag == DT_NEEDED):
                dt_needed.append(d_val_ptr)
            #
        #
        assert nsymbol > -1, "can not detect nsymbol by DT_HASH, DT_GNUHASH, not support now"

        f.seek(dyn_str_off)
        self.__dyn_str_buf = f.read(dyn_str_sz)
        self.__dyn_str_sz = dyn_str_sz

        f.seek(dyn_sym_off, 0)
        for i in range(0, nsymbol):
            sym_bytes = f.read(elf32_sym_sz)
            st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack("<IIIccH", sym_bytes)
            int_st_info = int.from_bytes(st_info, byteorder='little', signed = False)
            st_info_bind = ELFReader.__elf_st_bind(int_st_info)
            st_info_type = ELFReader.__elf_st_type(int_st_info)
            name = self.__st_name_to_name(st_name)
            d = {"name":name, "st_name":st_name, "st_value":st_value, "st_size":st_size, "st_info":st_info, "st_other":st_other, 
            "st_shndx":st_shndx, "st_info_bind":st_info_bind, "st_info_type":st_info_type}
            self.__dynsymols.append(d)
        #

        f.seek(rel_off, 0)
        rel_table = []
        for i in range(0, rel_count):
            rel_item_bytes = f.read(elf32_rel_sz)
            r_offset, r_info = struct.unpack("<II", rel_item_bytes)
            d = {"r_offset":r_offset, "r_info":r_info}
            r_info_sym = ELFReader.__elf32_r_sym(r_info)
            r_info_type = ELFReader.__elf32_r_type(r_info)
            d = {"r_offset":r_offset, "r_info":r_info, "r_info_type":r_info_type, "r_info_sym":r_info_sym}
            rel_table.append(d)
        #
        self.__rels["dynrel"] = rel_table

        f.seek(relplt_off, 0)
        relplt_table = []
        for i in range(0, relplt_count):
            rel_item_bytes = f.read(elf32_rel_sz)
            r_offset, r_info = struct.unpack("<II", rel_item_bytes)
            r_info_sym = ELFReader.__elf32_r_sym(r_info)
            r_info_type = ELFReader.__elf32_r_type(r_info)
            d = {"r_offset":r_offset, "r_info":r_info, "r_info_type":r_info_type, "r_info_sym":r_info_sym}
            relplt_table.append(d)
        #
        self.__rels["relplt"] = relplt_table
        print("ok")
        self.__so_needed = []
        for str_off in dt_needed:
            endId=self.__dyn_str_buf.find(b"\x00", str_off)
            so_name = self.__dyn_str_buf[str_off:endId]
            self.__so_needed.append(so_name.decode("utf-8"))
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

    def get_dyn_string_by_rel_sym(self, rel_sym):
        nsym = len(self.__dynsymols)
        assert rel_sym < nsym
        sym =  self.__dynsymols[rel_sym]
        st_name = sym["st_name"]
        r = self.__st_name_to_name(st_name)
        return r
    #

    def get_init_array(self):
        return self.__init_array_off, self.__init_array_size
    #

    def get_init(self):
        return self.__init_off
    #

    def get_so_need(self):
        return self.__so_needed
    #
#