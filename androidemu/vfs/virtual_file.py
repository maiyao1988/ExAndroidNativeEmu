class VirtualFile:

    def __init__(self, name, file_descriptor, name_in_system=None):
        self.name = name
        self.name_in_system = name_in_system
        self.descriptor = file_descriptor
    #
#