from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class DnsChain(_message.Message):
    __slots__ = ["data", "gpass", "gtype", "guri", "guser"]
    DATA_FIELD_NUMBER: _ClassVar[int]
    GPASS_FIELD_NUMBER: _ClassVar[int]
    GTYPE_FIELD_NUMBER: _ClassVar[int]
    GURI_FIELD_NUMBER: _ClassVar[int]
    GUSER_FIELD_NUMBER: _ClassVar[int]
    data: _containers.RepeatedScalarFieldContainer[str]
    gpass: str
    gtype: str
    guri: str
    guser: str
    def __init__(self, gtype: _Optional[str] = ..., guri: _Optional[str] = ..., guser: _Optional[str] = ..., gpass: _Optional[str] = ..., data: _Optional[_Iterable[str]] = ...) -> None: ...

class result(_message.Message):
    __slots__ = ["res"]
    RES_FIELD_NUMBER: _ClassVar[int]
    res: str
    def __init__(self, res: _Optional[str] = ...) -> None: ...
