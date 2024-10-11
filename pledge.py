import ctypes
import os
from typing import Iterable

_pledge = None
# noinspection PyBroadException
try:
    _pledge = ctypes.CDLL(None, use_errno=True).pledge
    _pledge.restype = ctypes.c_int
    _pledge.argtypes = ctypes.c_char_p, ctypes.c_char_p
except Exception:
    _pledge = None

_unveil = None
# noinspection PyBroadException
try:
    _unveil = ctypes.CDLL(None, use_errno=True).unveil
    _unveil.restype = ctypes.c_int
    _unveil.argtypes = ctypes.c_char_p, ctypes.c_char_p
except Exception:
    _unveil = None


def pledge(promises: str | Iterable[str] = None, execpromises: str | Iterable[str] = None) -> bool:
    if not _pledge:
        return False  # unimplemented

    if promises and not isinstance(promises, str):
        promises = ' '.join(promises)

    if execpromises and not isinstance(execpromises, str):
        execpromises = ' '.join(execpromises)

    r = _pledge(None if promises is None else promises.encode(),
                None if execpromises is None else execpromises.encode())
    if r == -1:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))

    return True


def unveil(path: str | bytes = None, permissions: str = None) -> bool:
    if not _unveil:
        return False  # unimplemented

    r = _unveil(path.encode() if isinstance(path, str) else path,
                None if permissions is None else permissions.encode())
    if r == -1:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))

    return True
