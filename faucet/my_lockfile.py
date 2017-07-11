"""Simple lockfile class used between faucet and the authentication controller app"""

import fcntl
import os

def lock(lockfile, flags):
    """Locks a interprocess file.
    Args:
        lockfile (str): name of file to lock.
        flags: os flags to use when locking. e.g. os.O_RDWR
             see https://docs.python.org/3/library/os.html#os.open for more
    Returns:
        filedescriptor of locked file.
    """
    fd = os.open(lockfile, flags)
    fcntl.lockf(fd, fcntl.LOCK_EX)
    return fd

def unlock(fd):
    """unlocks a file descriptor
    Args:
        fd (file descriptor)"""
    fcntl.lockf(fd, fcntl.LOCK_UN)
    os.close(fd)
