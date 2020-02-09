import os.path
import os

def vfs_path_to_system_path(vfs_root, path):
    if os.name == 'nt':
        path = path.replace(':', '_')
    #
    fullpath = None
    if (os.path.isabs(path)):
        fullpath = "%s/%s"%(vfs_root, path)
    else:
        fullpath = "%s/system/lib/%s"%(vfs_root, path)
    #
    return fullpath
#

def system_path_to_vfs_path(vfs_root, path):
    return os.path.relpath(path, vfs_root)
#