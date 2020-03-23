
STACK_ADDR = 0x10000000
STACK_SIZE = 0x00100000

HOOK_MEMORY_BASE = 0x01000000
HOOK_MEMORY_SIZE = 0x00200000 

MAP_ALLOC_BASE = 0x30000000
MAP_ALLOC_SIZE = 0xA0000000-MAP_ALLOC_BASE

BASE_ADDR = 0xCBBCB000

WRITE_FSTAT_TIMES = True

_configs = {}
import json
def global_config_init(cfg_path):
    global _configs
    with open(cfg_path, "r") as f:
        js = f.read()
        _configs = json.loads(js)
    #
#

def global_config_get(key):
    global _configs
    return _configs[key]
#
