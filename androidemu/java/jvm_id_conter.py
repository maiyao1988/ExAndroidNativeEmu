import itertools

g_next_jvm_id = itertools.count(start=1)
g_next_jvm_method_id = itertools.count(start=0xd2000000, step=4)
g_next_jvm_field_id = itertools.count(start=0xe2000000, step=4)

def next_cls_id():
    global g_next_jvm_id
    return next(g_next_jvm_id)
#

def next_method_id():
    global g_next_jvm_method_id
    return next(g_next_jvm_method_id)
#

def next_field_id():
    global g_next_jvm_field_id
    return next(g_next_jvm_field_id)
#
