
import logging
import posixpath
import sys
import unittest

from unicorn import *
from deofuse import cfg
from deofuse.cfg import CodeBlock
from deofuse.ins_helper import *
from deofuse.intruction_mgr import *


class TestAsm(unittest.TestCase):

    def test_disasm(self):
        block = CodeBlock(0x0007CA86, 0x0007CA94)
        ins_mgr = IntructionManger(True)
        with open("tests/bin/libcms.so", "rb") as f:
            codes = get_block_codes(f, block, ins_mgr)
            self.assertEqual(len(codes), 3)
        #
    #
    
#