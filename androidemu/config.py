
#注意，原有缺陷，libc_preinit init array中访问R1参数是从内核传过来的
#而这里直接将栈设成0,强行运行过去，因为R1刚好为0,否则会报unmap异常
#TODO 初始化libc时候R1参数模拟内核传过去的KernelArgumentBlock
STACK_ADDR = 0x00000000
STACK_SIZE = 0x00100000

HOOK_MEMORY_BASE = 0x1000000
HOOK_MEMORY_SIZE = 0x0200000  # 2 * 1024 * 1024 - 2MB

HEAP_BASE = 0x2000000
HEAP_SIZE = 0x08000000  # 2 * 1024 * 1024 - 2MB

BASE_ADDR = 0xCBBCB000

WRITE_FSTAT_TIMES = True
