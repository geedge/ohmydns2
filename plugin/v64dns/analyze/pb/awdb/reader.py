from __future__ import unicode_literals

try:
    import mmap
except ImportError:
    mmap = None

import struct

from awdb.compat import compat_ip_address, string_type
from awdb.const import MODE_AUTO, MODE_MMAP, MODE_FILE, MODE_MEMORY, MODE_FD
from awdb.decoder import Decoder
from awdb.errors import InvalidDatabaseError
from awdb.file import FileBuffer


class Reader(object):

    _DATA_SECTION_SEPARATOR_SIZE = 16
    _METADATA_START_MARKER = b"\xAB\xCD\xEFipplus360.com"

    _ipv4_start = None

    def __init__(self, database, mode=MODE_AUTO):
        if (mode == MODE_AUTO and mmap) or mode == MODE_MMAP:
            with open(database, 'rb') as db_file:
                self._buffer = mmap.mmap(db_file.fileno(),
                                         0,
                                         access=mmap.ACCESS_READ)
                self._buffer_size = self._buffer.size()
            filename = database
        elif mode in (MODE_AUTO, MODE_FILE):
            self._buffer = FileBuffer(database)
            self._buffer_size = self._buffer.size()
            filename = database
        elif mode == MODE_MEMORY:
            with open(database, 'rb') as db_file:
                self._buffer = db_file.read()
                self._buffer_size = len(self._buffer)
            filename = database
        elif mode == MODE_FD:
            self._buffer = database.read()
            self._buffer_size = len(self._buffer)
            filename = database.name
        else:
            raise ValueError(
                'Unsupported open mode ({0}). Only MODE_AUTO, MODE_FILE, '
                'MODE_MEMORY and MODE_FD are supported by the pure Python '
                'Reader'.format(mode))

        metadata_start = self._buffer.rfind(
            self._METADATA_START_MARKER, max(0,
                                             self._buffer_size - 128 * 1024))

        if metadata_start == -1:
            self.close()
            raise InvalidDatabaseError('Error opening database file ({0}). '
                                       'Is this a valid AW DB file?'
                                       ''.format(filename))

        metadata_start += len(self._METADATA_START_MARKER)
        metadata_decoder = Decoder(self._buffer, metadata_start)
        (metadata, _) = metadata_decoder.decode(metadata_start)
        self._metadata = Metadata(**metadata) 

        self._decoder = Decoder(
            self._buffer, self._metadata.search_tree_size +
            self._DATA_SECTION_SEPARATOR_SIZE)
        self.closed = False

    def metadata(self):
        return self._metadata

    def get(self, ip_address):
        (record, _) = self.get_with_prefix_len(ip_address)
        return record

    def get_with_prefix_len(self, ip_address):
        if isinstance(ip_address, string_type):
            address = compat_ip_address(ip_address)
        else:
            address = ip_address

        try:
            packed_address = bytearray(address.packed)
        except AttributeError:
            raise TypeError('argument 1 must be a string or ipaddress object')

        if address.version == 6 and self._metadata.ip_version == 4:
            raise ValueError(
                'Error looking up {0}. You attempted to look up '
                'an IPv6 address in an IPv4-only database.'.format(ip_address))

        (pointer, prefix_len) = self._find_address_in_tree(packed_address)

        if pointer:
            return self._resolve_data_pointer(pointer), prefix_len
        return None, prefix_len

    def _find_address_in_tree(self, packed):
        bit_count = len(packed) * 8
        node = self._start_node(bit_count)
        node_count = self._metadata.node_count

        i = 0
        while i < bit_count and node < node_count:
            bit = 1 & (packed[i >> 3] >> 7 - (i % 8))
            node = self._read_node(node, bit)
            i = i + 1

        if node == node_count:
            return 0, i
        if node > node_count:
            return node, i

        raise InvalidDatabaseError('Invalid node in search tree')

    def _start_node(self, length):
        if self._metadata.ip_version != 6 or length == 128:
            return 0

        if self._ipv4_start:
            return self._ipv4_start

        node = 0
        for _ in range(96):
            if node >= self._metadata.node_count:
                break
            node = self._read_node(node, 0)
        self._ipv4_start = node
        return node

    def _read_node(self, node_number, index):
        base_offset = node_number * self._metadata.node_byte_size

        record_size = self._metadata.record_size
        if record_size == 24:
            offset = base_offset + index * 3
            node_bytes = b'\x00' + self._buffer[offset:offset + 3]
        elif record_size == 28:
            offset = base_offset + 3 * index
            node_bytes = bytearray(self._buffer[offset:offset + 4])
            if index:
                node_bytes[0] = 0x0F & node_bytes[0]
            else:
                middle = (0xF0 & node_bytes.pop()) >> 4
                node_bytes.insert(0, middle)
        elif record_size == 32:
            offset = base_offset + index * 4
            node_bytes = self._buffer[offset:offset + 4]
        else:
            raise InvalidDatabaseError(
                'Unknown record size: {0}'.format(record_size))
        return struct.unpack(b'!I', node_bytes)[0]

    def _resolve_data_pointer(self, pointer):
        resolved = pointer - self._metadata.node_count + \
            self._metadata.search_tree_size

        if resolved >= self._buffer_size:
            raise InvalidDatabaseError(
                "The AW DB file's search tree is corrupt")

        (data, _) = self._decoder.decode(resolved)
        return data

    def close(self):
        if type(self._buffer) not in (str, bytes):
            self._buffer.close()
        self.closed = True

    def __exit__(self, *args):
        self.close()

    def __enter__(self):
        if self.closed:
            raise ValueError('Attempt to reopen a closed AW DB')
        return self


class Metadata(object):
    def __init__(self, **kwargs):
        self.node_count = kwargs['node_count']
        self.record_size = kwargs['record_size']
        self.ip_version = kwargs['ip_version']
        self.database_type = kwargs['database_type']
        self.languages = kwargs['languages']
        self.binary_format_major_version = kwargs[
            'binary_format_major_version']
        self.binary_format_minor_version = kwargs[
            'binary_format_minor_version']
        self.build_epoch = kwargs['build_epoch']
        self.description = kwargs['description']

    @property
    def node_byte_size(self):
        return self.record_size // 4

    @property
    def search_tree_size(self):
        return self.node_count * self.node_byte_size

    def __repr__(self):
        args = ', '.join('%s=%r' % x for x in self.__dict__.items())
        return '{module}.{class_name}({data})'.format(
            module=self.__module__,
            class_name=self.__class__.__name__,
            data=args)
