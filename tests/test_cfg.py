import logging
import posixpath
import sys
import unittest

from unicorn import *
from deofuse import cfg
from deofuse.cfg import CodeBlock

class TestCfg(unittest.TestCase):

    def hex_addr_assert(self, a, b):
        self.assertEqual(a, b, "0x%08X != 0x%08X"%(a, b))
    #

    def test_cfg_libc_pthread_create(self):
        cbs = [CodeBlock(0x0000D218, 0x0000D268), CodeBlock(0x0000D268, 0x0000D274), 
        CodeBlock(0x0000D274, 0x0000D28C), CodeBlock(0x0000D28C, 0x0000D2C8), 
        CodeBlock(0x0000D2C8, 0x0000D2D4), CodeBlock(0x0000D2D4, 0x0000D314), CodeBlock(0x0000D314, 0x0000D32C), 
        CodeBlock(0x0000D32C, 0x0000D348), CodeBlock(0x0000D348, 0x0000D350), CodeBlock(0x0000D350, 0x0000D364), 
        CodeBlock(0x0000D364, 0x0000D378), CodeBlock(0x0000D378, 0x0000D3AC), CodeBlock(0x0000D3AC, 0x0000D3D8), 
        CodeBlock(0x0000D3D8, 0x0000D3E8), CodeBlock(0x0000D3E8, 0x0000D408), CodeBlock(0x0000D408, 0x0000D414), 
        CodeBlock(0x0000D414, 0x0000D454), CodeBlock(0x0000D454, 0x0000D468), CodeBlock(0x0000D468, 0x0000D47C), 
        CodeBlock(0x0000D47C, 0x0000D484), CodeBlock(0x0000D484, 0x0000D4B4), CodeBlock(0x0000D4B4, 0x0000D4C8), 
        CodeBlock(0x0000D4C8, 0x0000D4D8), CodeBlock(0x0000D4D8, 0x0000D518)]

        with open("vfs/system/lib/libc.so", "rb") as f:
            blocks = cfg.create_cfg(f, 0x0000D218, 768, False)
            #print(blocks[9])
            #print(blocks[9].parent)
            #print(blocks[9].childs)
            #print(blocks)
            self.assertEqual(len(cbs), len(blocks))
            for i in range(0, len(cbs)):
                self.hex_addr_assert(cbs[i].start, blocks[i].start)
                self.hex_addr_assert(cbs[i].end, blocks[i].end)
            #
            b = blocks[9]
            self.hex_addr_assert(b.start, 0x0000D350)
            self.hex_addr_assert(b.end, 0x0000D364)
            self.assertEqual(len(b.parent), 3)
            self.assertEqual(len(b.childs), 0)
        #
    #


    def test_cfg_bangbang_tbb_tbh(self):
        cbs = [CodeBlock(0x0001B180, 0x0001B1C4), CodeBlock(0x0001B1C4, 0x0001B1CA), 
        CodeBlock(0x0001B1CA, 0x0001B1CE), CodeBlock(0x0001B1CE, 0x0001B1D2), 
        CodeBlock(0x0001B1E0, 0x0001B1E2), CodeBlock(0x0001B1E2, 0x0001B1EC), 
        CodeBlock(0x0001B1EC, 0x0001B1F4), CodeBlock(0x0001B1F4, 0x0001B1FC), 
        CodeBlock(0x0001B1FC, 0x0001B204), CodeBlock(0x0001B204, 0x0001B208), 
        CodeBlock(0x0001B208, 0x0001B248), CodeBlock(0x0001B248, 0x0001B27E), 
        CodeBlock(0x0001B27E, 0x0001B2A8), CodeBlock(0x0001B2A8, 0x0001B2AC), 
        CodeBlock(0x0001B2AC, 0x0001B2B2), CodeBlock(0x0001B2B2, 0x0001B2B6), 
        CodeBlock(0x0001B2B6, 0x0001B2BA), CodeBlock(0x0001B2CC, 0x0001B37A), 
        CodeBlock(0x0001B37A, 0x0001B382), CodeBlock(0x0001B382, 0x0001B38A), 
        CodeBlock(0x0001B38A, 0x0001B392), CodeBlock(0x0001B392, 0x0001B39A), 
        CodeBlock(0x0001B39A, 0x0001B39E), CodeBlock(0x0001B39E, 0x0001B3BC), 
        CodeBlock(0x0001B3BC, 0x0001B3DC), CodeBlock(0x0001B3DC, 0x0001B3E8), 
        CodeBlock(0x0001B3E8, 0x0001B3FC), CodeBlock(0x0001B3FC, 0x0001B400), 
        CodeBlock(0x0001B400, 0x0001B402), CodeBlock(0x0001B402, 0x0001B406), 
        CodeBlock(0x0001B406, 0x0001B410), CodeBlock(0x0001B410, 0x0001B414), 
        CodeBlock(0x0001B414, 0x0001B41A), CodeBlock(0x0001B41A, 0x0001B430), 
        CodeBlock(0x0001B430, 0x0001B438), CodeBlock(0x0001B438, 0x0001B43A), 
        CodeBlock(0x0001B43A, 0x0001B442), CodeBlock(0x0001B442, 0x0001B446), 
        CodeBlock(0x0001B446, 0x0001B448), CodeBlock(0x0001B448, 0x0001B44C), 
        CodeBlock(0x0001B44C, 0x0001B450), CodeBlock(0x0001B450, 0x0001B46A), 
        CodeBlock(0x0001B46A, 0x0001B472), CodeBlock(0x0001B472, 0x0001B47C), 
        CodeBlock(0x0001B47C, 0x0001B47E), CodeBlock(0x0001B47E, 0x0001B486), 
        CodeBlock(0x0001B486, 0x0001B49A), CodeBlock(0x0001B49A, 0x0001B49E), CodeBlock(0x0001B49E, 0x0001B4A0),
         CodeBlock(0x0001B4A0, 0x0001B4A4), CodeBlock(0x0001B4A4, 0x0001B4A8), CodeBlock(0x0001B4A8, 0x0001B4B8), 
         CodeBlock(0x0001B4B8, 0x0001B4BA), CodeBlock(0x0001B4BA, 0x0001B4BE), CodeBlock(0x0001B4BE, 0x0001B4C4), 
         CodeBlock(0x0001B4C4, 0x0001B4D4), CodeBlock(0x0001B4D4, 0x0001B4D6), CodeBlock(0x0001B4D6, 0x0001B4E4), 
         CodeBlock(0x0001B4FC, 0x0001B500), CodeBlock(0x0001B500, 0x0001B502), 
         CodeBlock(0x0001B502, 0x0001B506), CodeBlock(0x0001B506, 0x0001B514), CodeBlock(0x0001B514, 0x0001B54C), 
         CodeBlock(0x0001B54C, 0x0001B638), CodeBlock(0x0001B638, 0x0001B64A), CodeBlock(0x0001B64A, 0x0001B65C), 
         CodeBlock(0x0001B65C, 0x0001B66C), CodeBlock(0x0001B66C, 0x0001B7E4), CodeBlock(0x0001B7E4, 0x0001B93E), 
         CodeBlock(0x0001B93E, 0x0001B940), CodeBlock(0x0001B940, 0x0001B960), CodeBlock(0x0001B960, 0x0001BA0E), 
         CodeBlock(0x0001BA0E, 0x0001BA96), CodeBlock(0x0001BA96, 0x0001BDB4), CodeBlock(0x0001BDB4, 0x0001BDCA),
          CodeBlock(0x0001BDCA, 0x0001BDDA), CodeBlock(0x0001BDDA, 0x0001BDE8), CodeBlock(0x0001BDE8, 0x0001BDEE), 
          CodeBlock(0x0001BDEE, 0x0001BF26), CodeBlock(0x0001BF26, 0x0001BF30), CodeBlock(0x0001BF30, 0x0001CC78), 
          CodeBlock(0x0001CC78, 0x0001CD5E), CodeBlock(0x0001CD5E, 0x0001CDCC), CodeBlock(0x0001CDCC, 0x0001CDCE), 
          CodeBlock(0x0001CDCE, 0x0001CDE4), CodeBlock(0x0001CDE4, 0x0001CDEA), CodeBlock(0x0001CDEA, 0x0001CDEC), 
          CodeBlock(0x0001CDEC, 0x0001CE76), CodeBlock(0x0001CE76, 0x0001CE86), CodeBlock(0x0001CE86, 0x0001CED0), 
          CodeBlock(0x0001CED0, 0x0001CEDA), CodeBlock(0x0001CEDA, 0x0001D022), CodeBlock(0x0001D022, 0x0001D024), 
          CodeBlock(0x0001D024, 0x0001D058), CodeBlock(0x0001D058, 0x0001D05E), CodeBlock(0x0001D05E, 0x0001D08C), 
          CodeBlock(0x0001D08C, 0x0001D090), CodeBlock(0x0001D090, 0x0001D094), CodeBlock(0x0001D094, 0x0001D098), 
          CodeBlock(0x0001D0A4, 0x0001D0B2), CodeBlock(0x0001D0B2, 0x0001D0D0), CodeBlock(0x0001D0D0, 0x0001D0F0), 
          CodeBlock(0x0001D0F0, 0x0001D108), CodeBlock(0x0001D108, 0x0001D114), CodeBlock(0x0001D114, 0x0001D116), 
          CodeBlock(0x0001D116, 0x0001D126), CodeBlock(0x0001D126, 0x0001D136), CodeBlock(0x0001D136, 0x0001D150), 
          CodeBlock(0x0001D150, 0x0001D156), CodeBlock(0x0001D156, 0x0001D162), CodeBlock(0x0001D162, 0x0001D164), 
          CodeBlock(0x0001D164, 0x0001D168), CodeBlock(0x0001D168, 0x0001D16E), CodeBlock(0x0001D16E, 0x0001D172), 
          CodeBlock(0x0001D172, 0x0001D178), CodeBlock(0x0001D178, 0x0001D17C), CodeBlock(0x0001D17C, 0x0001D186), 
          CodeBlock(0x0001D186, 0x0001D18A), CodeBlock(0x0001D18A, 0x0001D194), CodeBlock(0x0001D194, 0x0001D198), 
          CodeBlock(0x0001D198, 0x0001D19A), CodeBlock(0x0001D19A, 0x0001D1A0), CodeBlock(0x0001D1A0, 0x0001D1FC), 
          CodeBlock(0x0001D1FC, 0x0001D20A), CodeBlock(0x0001D20A, 0x0001D21C), CodeBlock(0x0001D21C, 0x0001D22C), 
          CodeBlock(0x0001D22C, 0x0001D244), CodeBlock(0x0001D244, 0x0001D246), CodeBlock(0x0001D246, 0x0001D24C), 
          CodeBlock(0x0001D24C, 0x0001D260), CodeBlock(0x0001D260, 0x0001D276), CodeBlock(0x0001D276, 0x0001D288), 
          CodeBlock(0x0001D288, 0x0001D28C), CodeBlock(0x0001D28C, 0x0001D296), CodeBlock(0x0001D296, 0x0001D356), 
          CodeBlock(0x0001D356, 0x0001D360), CodeBlock(0x0001D360, 0x0001D364), CodeBlock(0x0001D364, 0x0001D376), 
          CodeBlock(0x0001D376, 0x0001D380), CodeBlock(0x0001D380, 0x0001D38C), CodeBlock(0x0001D38C, 0x0001D3A0), 
          CodeBlock(0x0001D3A0, 0x0001D3A4), CodeBlock(0x0001D3A4, 0x0001D3A6), CodeBlock(0x0001D3A6, 0x0001D3A8), 
          CodeBlock(0x0001D3A8, 0x0001D3B8), CodeBlock(0x0001D3B8, 0x0001D3CE), CodeBlock(0x0001D3CE, 0x0001D3D4), 
          CodeBlock(0x0001D3D4, 0x0001D3D8), CodeBlock(0x0001D3D8, 0x0001D3DC), CodeBlock(0x0001D406, 0x0001D418), 
          CodeBlock(0x0001D418, 0x0001D446), CodeBlock(0x0001D446, 0x0001D460), CodeBlock(0x0001D460, 0x0001D490), 
          CodeBlock(0x0001D490, 0x0001D494), CodeBlock(0x0001D494, 0x0001D508), CodeBlock(0x0001D508, 0x0001D522), 
          CodeBlock(0x0001D522, 0x0001D526), CodeBlock(0x0001D526, 0x0001D564), CodeBlock(0x0001D564, 0x0001D578), 
          CodeBlock(0x0001D578, 0x0001D582), CodeBlock(0x0001D582, 0x0001D59A), CodeBlock(0x0001D59A, 0x0001D5A0), 
          CodeBlock(0x0001D5A0, 0x0001D5E0), CodeBlock(0x0001D5E0, 0x0001D5E2), CodeBlock(0x0001D5E2, 0x0001D5E6), 
          CodeBlock(0x0001D5E6, 0x0001D5EA), CodeBlock(0x0001D5EA, 0x0001D5EE), CodeBlock(0x0001D5F6, 0x0001D5FE), 
          CodeBlock(0x0001D5FE, 0x0001D60A), CodeBlock(0x0001D60A, 0x0001D618), CodeBlock(0x0001D618, 0x0001D63A), 
          CodeBlock(0x0001D63A, 0x0001D646), CodeBlock(0x0001D646, 0x0001D64A), CodeBlock(0x0001D64A, 0x0001D64E), 
          CodeBlock(0x0001D64E, 0x0001D65C), CodeBlock(0x0001D65C, 0x0001D66A), CodeBlock(0x0001D66A, 0x0001D66E), 
          CodeBlock(0x0001D66E, 0x0001D672), CodeBlock(0x0001D672, 0x0001D674), CodeBlock(0x0001D674, 0x0001D678), 
          CodeBlock(0x0001D678, 0x0001D694), CodeBlock(0x0001D694, 0x0001D6A0), CodeBlock(0x0001D6A0, 0x0001D6A2), 
          CodeBlock(0x0001D6A2, 0x0001D6A6), CodeBlock(0x0001D6A6, 0x0001D6AA), CodeBlock(0x0001D6AA, 0x0001D6B0), 
          CodeBlock(0x0001D6B0, 0x0001D6B8), CodeBlock(0x0001D6B8, 0x0001D6BA), CodeBlock(0x0001D6BA, 0x0001D6BE), 
          CodeBlock(0x0001D6BE, 0x0001D6FE), CodeBlock(0x0001D6FE, 0x0001D702), CodeBlock(0x0001D702, 0x0001D708), 
          CodeBlock(0x0001D708, 0x0001D734), CodeBlock(0x0001D734, 0x0001D74A), CodeBlock(0x0001D74A, 0x0001D756), 
          CodeBlock(0x0001D756, 0x0001D76A), CodeBlock(0x0001D76A, 0x0001D776), CodeBlock(0x0001D776, 0x0001D77A), 
          CodeBlock(0x0001D77A, 0x0001D784), CodeBlock(0x0001D784, 0x0001D794), CodeBlock(0x0001D794, 0x0001D7BE), 
          CodeBlock(0x0001D7BE, 0x0001D7CC), CodeBlock(0x0001D7CC, 0x0001D7EC), CodeBlock(0x0001D7EC, 0x0001D80A), 
          CodeBlock(0x0001D80A, 0x0001D80C), CodeBlock(0x0001D80C, 0x0001D93E), CodeBlock(0x0001D93E, 0x0001D944), 
          CodeBlock(0x0001D944, 0x0001D948), CodeBlock(0x0001D948, 0x0001D94C), CodeBlock(0x0001D96C, 0x0001D980), 
          CodeBlock(0x0001D980, 0x0001D99E), CodeBlock(0x0001D99E, 0x0001D9A6), CodeBlock(0x0001D9A6, 0x0001D9C0), 
          CodeBlock(0x0001D9C0, 0x0001D9C6), CodeBlock(0x0001D9C6, 0x0001D9CC), CodeBlock(0x0001D9CC, 0x0001D9D4),
           CodeBlock(0x0001D9D4, 0x0001D9FA), CodeBlock(0x0001D9FA, 0x0001DA5C), CodeBlock(0x0001DA5C, 0x0001DA66), 
           CodeBlock(0x0001DA66, 0x0001DA6E), CodeBlock(0x0001DA6E, 0x0001DA76), CodeBlock(0x0001DA76, 0x0001DA7E), 
           CodeBlock(0x0001DA7E, 0x0001DA82), CodeBlock(0x0001DA82, 0x0001DAA6), CodeBlock(0x0001DAA6, 0x0001DABA), 
           CodeBlock(0x0001DABA, 0x0001DAFE), CodeBlock(0x0001DAFE, 0x0001DB04), CodeBlock(0x0001DB04, 0x0001DB08), 
           CodeBlock(0x0001DB08, 0x0001DB0C), CodeBlock(0x0001DB16, 0x0001DB2E), CodeBlock(0x0001DB2E, 0x0001DB34), 
           CodeBlock(0x0001DB34, 0x0001DB3A), CodeBlock(0x0001DB3A, 0x0001DB66), CodeBlock(0x0001DB66, 0x0001DB6E), 
           CodeBlock(0x0001DB6E, 0x0001DB8E), CodeBlock(0x0001DB8E, 0x0001DB9C), CodeBlock(0x0001DB9C, 0x0001DB9E), 
           CodeBlock(0x0001DB9E, 0x0001DBA2), CodeBlock(0x0001DBA2, 0x0001DBAC), CodeBlock(0x0001DBAC, 0x0001DBCA), 
           CodeBlock(0x0001DBCA, 0x0001DC00), CodeBlock(0x0001DC00, 0x0001DC06), CodeBlock(0x0001DC06, 0x0001DC0A), 
           CodeBlock(0x0001DC0A, 0x0001DC0E), CodeBlock(0x0001DC0E, 0x0001DC10), CodeBlock(0x0001DC10, 0x0001DC14), 
           CodeBlock(0x0001DC14, 0x0001DC2C), CodeBlock(0x0001DC2C, 0x0001DC30), CodeBlock(0x0001DC30, 0x0001DC36), 
           CodeBlock(0x0001DC36, 0x0001DC3C), CodeBlock(0x0001DC3C, 0x0001DC50), CodeBlock(0x0001DC50, 0x0001DC64), 
           CodeBlock(0x0001DC64, 0x0001DC94), CodeBlock(0x0001DC94, 0x0001DCA6), CodeBlock(0x0001DCA6, 0x0001DCC4), 
           CodeBlock(0x0001DCC4, 0x0001DCDC), CodeBlock(0x0001DCDC, 0x0001DCE2), CodeBlock(0x0001DCE2, 0x0001DCE6), 
           CodeBlock(0x0001DCE6, 0x0001DCEE), CodeBlock(0x0001DCEE, 0x0001DCF0), CodeBlock(0x0001DCF0, 0x0001DCF4), 
           CodeBlock(0x0001DCF4, 0x0001DCFE), CodeBlock(0x0001DCFE, 0x0001DD02), CodeBlock(0x0001DD02, 0x0001DD0A), 
           CodeBlock(0x0001DD0A, 0x0001DD0E), CodeBlock(0x0001DD0E, 0x0001DD1C), CodeBlock(0x0001DD1C, 0x0001DD20), 
           CodeBlock(0x0001DD20, 0x0001DD26), CodeBlock(0x0001DD26, 0x0001DD60), CodeBlock(0x0001DD60, 0x0001DD7E), 
           CodeBlock(0x0001DD7E, 0x0001DD86), CodeBlock(0x0001DD86, 0x0001DDB4), CodeBlock(0x0001DDB4, 0x0001DDEA), 
           CodeBlock(0x0001DDEA, 0x0001DDF0), CodeBlock(0x0001DDF0, 0x0001DDF6), CodeBlock(0x0001DDF6, 0x0001DDFA), 
           CodeBlock(0x0001DDFA, 0x0001DE82), CodeBlock(0x0001DE82, 0x0001DE8A), CodeBlock(0x0001DE8A, 0x0001DE8E), 
           CodeBlock(0x0001DE94, 0x0001DEB8), CodeBlock(0x0001DEB8, 0x0001DEBC), CodeBlock(0x0001DEBC, 0x0001DECA), 
           CodeBlock(0x0001DECA, 0x0001DF02), CodeBlock(0x0001DF02, 0x0001DF14), CodeBlock(0x0001DF14, 0x0001DF26), 
           CodeBlock(0x0001DF26, 0x0001DF30), CodeBlock(0x0001DF30, 0x0001DF34), CodeBlock(0x0001DF34, 0x0001DF40), 
           CodeBlock(0x0001DF40, 0x0001DF44), CodeBlock(0x0001DF44, 0x0001DF4C)]

        with open("tests/bin/libSecShell.so", "rb") as f:
            blocks = cfg.create_cfg(f, 0x0001B180, 11724, True)
            self.assertEqual(len(cbs), len(blocks))
            for i in range(0, len(cbs)):
                self.hex_addr_assert(cbs[i].start, blocks[i].start)
                self.hex_addr_assert(cbs[i].end, blocks[i].end)
            #
        #
    #
#
