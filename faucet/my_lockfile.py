import fcntl
import os

def lock(lockfile, flags):
    fd = os.open(lockfile, flags)
    fcntl.lockf(fd, fcntl.LOCK_EX)
    return fd

def unlock(fd):
    fcntl.lockf(fd, fcntl.LOCK_UN)
    os.close(fd)
