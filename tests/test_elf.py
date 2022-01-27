import logging
import posixpath
import sys
import unittest
from androidemu.internal.elf_reader import ELFReader

class TestElf(unittest.TestCase):

    def test_readelf32(self):
        r = ELFReader("tests/bin/libcms.so")
        rels = r.get_rels()

        dynrel = rels["dynrel"]
        n=len(dynrel)
        self.assertEqual(n, 2277)
        item = dynrel[2276]

        r_info_sym = item["r_info_sym"]
        sym_str = r.get_dyn_string_by_rel_sym(r_info_sym)
        self.assertEqual(sym_str, "JNI_OnLoad")


        relplt = rels["relplt"]
        n=len(relplt)
        self.assertEqual(n, 308)
        item = relplt[9]

        r_info_sym = item["r_info_sym"]
        sym_str = r.get_dyn_string_by_rel_sym(r_info_sym)
        self.assertEqual(sym_str, "getuid")

        so_needed = r.get_so_need()
        self.assertTrue("libc.so" in so_needed)
    #


    def test_readelf64(self):
        r = ELFReader("vfs/system/lib64/libc.so")
        rels = r.get_rels()
        dynrel = rels["dynrel"]

        n=len(dynrel)
        self.assertEqual(n, 1314)
        item = dynrel[1313]

        r_info_sym = item["r_info_sym"]
        sym_str = r.get_dyn_string_by_rel_sym(r_info_sym)
        self.assertEqual(sym_str, "isxdigit")


        relplt = rels["relplt"]
        n=len(relplt)
        self.assertEqual(n, 481)
        item = relplt[9]
        self.assertEqual(item["r_offset"], 0x0000000d6ec0)

        r_info_sym = item["r_info_sym"]
        sym_str = r.get_dyn_string_by_rel_sym(r_info_sym)
        self.assertEqual(sym_str, "ns_put16")

        so_needed = r.get_so_need()
        self.assertTrue("libdl.so" in so_needed)
    #

    def test_load_bias(self):
        #测试有load_bias情况下是否正确
        r = ELFReader("vfs/system/lib64/libc++.so")
        
        rels = r.get_rels()

        relplt = rels["relplt"]
        self.assertEqual(len(relplt), 449)
        item = relplt[11]
        self.assertEqual(item["r_offset"], 0x0000000f4cb8)
        sym_str = r.get_dyn_string_by_rel_sym(item["r_info_sym"])
        self.assertEqual(sym_str, "_Unwind_GetRegionStart")
        so_needed = r.get_so_need()
        self.assertTrue("libc.so" in so_needed)
        self.assertTrue("libm.so" in so_needed)
        self.assertTrue("libdl.so" in so_needed)

    #


    def test_libart(self):
        #测试有load_bias情况下是否正确
        r = ELFReader("vfs/system/lib64/libart.so")
        rels = r.get_rels()
        relplt = rels["relplt"]
        syms = r.get_symbols()
        self.assertEqual(len(syms), 5872)
        item = relplt[10]
        sym_str = r.get_dyn_string_by_rel_sym(item["r_info_sym"])
        self.assertEqual(sym_str, "__register_frame_info")
        so_needed = r.get_so_need()
        self.assertTrue("libc.so" in so_needed)
        self.assertTrue("libc++.so" in so_needed)

#