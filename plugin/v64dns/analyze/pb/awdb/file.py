import os

try:
    from multiprocessing import Lock
except ImportError:
    from threading import Lock


class FileBuffer(object):
    def __init__(self, database):
        self._handle = open(database, 'rb')
        self._size = os.fstat(self._handle.fileno()).st_size
        if not hasattr(os, 'pread'):
            self._lock = Lock()

    def __getitem__(self, key):
        if isinstance(key, slice):
            return self._read(key.stop - key.start, key.start)
        if isinstance(key, int):
            return self._read(1, key)[0]
        raise TypeError("Invalid argument type.")

    def rfind(self, needle, start):
        pos = self._read(self._size - start - 1, start).rfind(needle)
        if pos == -1:
            return pos
        return start + pos

    def size(self):
        return self._size

    def close(self):
        self._handle.close()

    if hasattr(os, 'pread'):

        def _read(self, buffersize, offset):
            return os.pread(self._handle.fileno(), buffersize, offset)

    else:

        def _read(self, buffersize, offset):
            with self._lock:
                self._handle.seek(offset)
                return self._handle.read(buffersize)
