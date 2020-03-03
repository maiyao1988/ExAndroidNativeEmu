# ExAndroidNativeEmu

This is a personal improved version of [AndroidNativeEmu](https://github.com/AeonLucid/AndroidNativeEmu).Allow running android elf code on pc.

## Difference between AndroidNativeEmu
 - Rewrite memory mapping module, fully support jemalloc
 - More debug utils, pretty printing for instruction and memory.
 - Some misc bug fix
 - Stop all runing when getting exception  instead of just skiping one emulator runing for easily bug detecting...
 - Support ELF DT_INIT call
 - Auto Load dependency so.
 - auto generate /proc/\[pid\]/maps according to current memory map
 - fix R_ARM_ABS32 relocation bug.
 - use program header to load so instead of section header
 
## TODO
 - Simulate linker TLS initialization.
 - Support well known virtual file like /proc/self/maps...
 - ~~Get rid of dependency on Section Header when loading ELF~~.
 
## Usage

> In the future this will be possible through pypi.

Make sure you are using python 3.7.

1. Clone the repository
2. Run `pip install -r requirements.txt`
3. Run `python example_jni.py`

> If you have trouble getting the `keystone-engine` dependency on Windows (as I did):
> 1. Clone their [repository](https://github.com/keystone-engine/keystone)
> 2. Open a terminal in `bindings/python`
> 3. Run `python setup.py install` (Make sure you are using python 3.7)
> 4. Download their `Windows - Core engine` package [here](http://www.keystone-engine.org/download/) for your python arch.
> 5. Put the `keystone.dll` in `C:\location_to_python\Lib\site-packages\keystone\`.

## Dependencies

- [Unicorn CPU emulator framework](https://github.com/unicorn-engine/unicorn)
- [Keystone assembler framework](https://github.com/keystone-engine/keystone)


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
