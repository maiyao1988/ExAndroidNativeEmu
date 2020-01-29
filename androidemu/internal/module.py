class Module:

    """
    :type filename str
    :type base int
    :type size int
    """
    def __init__(self, filename, address, size, symbols_resolved, init_addr, init_array=[]):
        self.filename = filename
        self.base = address
        self.size = size
        self.symbols = symbols_resolved
        self.symbol_lookup = dict()
        self.init_addr = init_addr
        self.init_array = list(init_array)

        # Create fast lookup.
        for symbol_name, symbol in self.symbols.items():
            if symbol.address != 0:
                self.symbol_lookup[symbol.address] = (symbol_name, symbol)

    def find_symbol(self, name):
        if name in self.symbols:
            return self.symbols[name]
        return None

    def is_symbol_addr(self, addr):
        if addr in self.symbol_lookup:
            return  self.symbol_lookup[addr][0]
        elif addr+1 in self.symbol_lookup:
            return  self.symbol_lookup[addr+1][0]
        else:
            return None

    def call_init(self, emu):                
        if (self.init_addr != 0):
            print("Calling init 0x%08X for: %s " % (self.init_addr, self.filename))
            emu.call_native(self.init_addr)
        #
        for fun_ptr in self.init_array:
            print("Calling Init_array %s function: 0x%08X " %(self.filename, fun_ptr))
            emu.call_native(fun_ptr)
        #
        
    #

