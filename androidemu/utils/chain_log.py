import sys

class ChainLogger:
    def __init__(self, base_fd, path):
        self.terminal = base_fd
        self.path = path
        self.log = None
    #
    def write(self, message):
        self.terminal.write(message)
        if (self.log == None):
            self.log = open(self.path, "w")
        #
        self.log.write(message)  
    #

    def flush(self):
        #this flush method is needed for python 3 compatibility.
        #this handles the flush command by doing nothing.
        #you might want to specify some extra behavior here.
        self.log.flush()
    #
#