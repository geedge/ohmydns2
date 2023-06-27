import awdb.reader

try:
    import awdb.extension
except ImportError:
    awdb.extension = None

from awdb.const import (MODE_AUTO, MODE_MMAP, MODE_MMAP_EXT, MODE_FILE,
                             MODE_MEMORY, MODE_FD)


def open_database(database, mode=MODE_AUTO):
    has_extension = awdb.extension and hasattr(awdb.extension,
                                                    'Reader')
    if (mode == MODE_AUTO and has_extension) or mode == MODE_MMAP_EXT:
        if not has_extension:
            raise ValueError(
                "MODE_MMAP_EXT requires the awdb.extension module to be available"
            )
        return awdb.extension.Reader(database)
    if mode in (MODE_AUTO, MODE_MMAP, MODE_FILE, MODE_MEMORY, MODE_FD):
        return awdb.reader.Reader(database, mode)
    raise ValueError('Unsupported open mode: {0}'.format(mode))


def Reader(database):  
    return open_database(database)


__title__ = 'awdb'
__version__ = '1.5.2'
__author__ = ''
__license__ = 'Apache License, Version 2.0'
__copyright__ = 'Copyright 2013-2020 AW, Inc.'
