import logging
import posixpath
import sys
import unittest
from androidemu.internal.elf_reader import ELFReader

class TestNative(unittest.TestCase):

    def test_readelf(self):
        # Initialize emulator
        with open("tests/bin/libcms.so", "rb") as f:
            r = ELFReader(f)
            rels = r.get_rels()
            for k in rels:
                print("symtable %s"%k)
                tbl = rels[k]
                for item in tbl:
                    r_info_sym = item["r_info_sym"]
                    sym_str = r.get_dyn_string_by_rel_sym(r_info_sym)
                    print("%08x %08x %d %s"%(item["r_offset"], item["r_info"], item["r_info_type"], sym_str))
                #
            #
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
    #