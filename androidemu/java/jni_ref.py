
class jobject:

    def __init__(self, value=None):
        self.value = value
    #
#

class jclass(jobject):

    def __init__(self, value=None):
        super().__init__(value)


