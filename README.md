# ExAndroidNativeEmu

This is a personal improved version of [AndroidNativeEmu](https://github.com/AeonLucid/AndroidNativeEmu).Allow running android elf code on pc.

## Improvment compare with AndroidNativeEmu
 - Rewrite memory mapping module, fully support jemalloc
 - More debug utils, pretty printing for instruction and memory.
 - Some misc bug fix
 - Stop all runing when getting exception  instead of just skiping one emulator runing for easily bug detecting...
 - Auto Load dependency so.
 - Auto generate /proc/\[pid\]/maps according to current memory map
 - Fix R_ARM_ABS32 relocation bug.
 - Use program header to load so instead of section header
 - Support Java reflection
 - Support Arm64
 - Support multi-threaded like pthread_create etc.
 - Add Function hook feature
 
## TODO
 - ~~Simulate linker TLS initialization.~~
 - ~~Support well known virtual file like /proc/self/maps...~~
 - ~~Get rid of dependency on Section Header when loading ELF~~.
 
## Usage

> In the future this will be possible through pypi.

Make sure you are using python 3.7 above.

1. Clone the repository
2. Run `pip install -r requirements.txt`
3. Run `python example_jni.py`


## Dependencies

- [Unicorn CPU emulator framework](https://github.com/unicorn-engine/unicorn)


### Text sources
- https://greek0.net/elf.html
- https://stackoverflow.com/questions/13908276/loading-elf-file-in-c-in-user-space
- https://programtalk.com/python-examples/pyelftools.elftools.elf.relocation.Relocation/
- http://infocenter.arm.com/help/topic/com.arm.doc.ihi0044f/IHI0044F_aaelf.pdf
- https://wiki.osdev.org/ELF_Tutorial
- https://docs.oracle.com/javase/7/docs/technotes/guides/jni/spec/functions.html
- https://android.googlesource.com/platform/dalvik/+/donut-release/vm/Jni.c

### Code sources
- https://github.com/lunixbochs/usercorn
- https://github.com/slick1015/pad_unpacker (SVC 0 instruction)
- https://github.com/AeonLucid/AndroidNativeEmu
