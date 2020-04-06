# https://docs.oracle.com/javase/7/docs/api/constant-values.html

MODIFIER_PUBLIC = 1
MODIFIER_PRIVATE = 2
MODIFIER_PROTECTED = 4
MODIFIER_STATIC = 8
MODIFIER_FINAL = 16
MODIFIER_SYNCHRONIZED = 32
MODIFIER_VOLATILE = 64
MODIFIER_TRANSIENT = 128
MODIFIER_NATIVE = 256
MODIFIER_INTERFACE = 512
MODIFIER_ABSTRACT = 1024
MODIFIER_STRICT = 2048

#注意，这个返回值是给java函数返回null的时候用，返回null与python的None不是一个概念
#python 的None在本系统设计里面表示函数没有返回值，与返回Null(0)有本质上的区别，请不要混淆
JAVA_NULL = 0