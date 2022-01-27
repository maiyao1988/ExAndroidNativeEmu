
STACK_ADDR = 0x10000000
STACK_SIZE = 0x00100000

BRIDGE_MEMORY_BASE = 0x01000000
BRIDGE_MEMORY_SIZE = 0x00200000

TLS_BASE = 0x02000000
TLS_SIZE = 0x1000

STOP_MEMORY_BASE = 0x03000000
STOP_MEMORY_SIZE = 0x00001000

TLS_SIZE = 0x1000

MAP_ALLOC_BASE = 0x30000000
MAP_ALLOC_SIZE = 0xA0000000-MAP_ALLOC_BASE
JMETHOD_ID_BASE = 0xd2000000
JFIELD_ID_BASE = 0xe2000000
BASE_ADDR = 0xCBBCB000

WRITE_FSTAT_TIMES = True

import json
class Config:

    def __init__(self, cfg_path):
        with open(cfg_path, "r") as f:
            js = f.read()
            self.__configs = json.loads(js)
        #
    #

    def get(self, key, def_val = None):
        if (key in self.__configs):
            return self.__configs[key]
        return def_val
    #
#