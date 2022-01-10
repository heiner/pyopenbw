# See
#   https://developers.google.com/protocol-buffers/docs/encoding
#

import enum
import io

FIXED32_SIZE = 4
FIXED64_SIZE = 8


class WireType(enum.IntEnum):
    VARINT = 0  # int32, int64, uint32, uint64, sint32, sint64, bool, enum
    FIXED64 = 1  # fixed64, sfixed64, double
    LENGTH_DELIMITED = 2  # string, bytes, embedded messages, packed repeated fields
    START_GROUP = 3  # groups (deprecated)
    END_GROUP = 4  # groups (deprecated)
    FIXED32 = 5  # fixed32, sfixed32, float


def read_varint(stream):
    result = 0
    pos = 0
    while True:
        b = stream.read(1)
        try:
            b = ord(b)
        except TypeError:
            if not pos:
                return
            raise

        if b == 0 and pos != 0:
            raise ValueError("Illegal input")

        result |= (b & 0x7F) << pos
        if not b & 0x80:
            return result
        pos += 7


def read_value(stream, wire_type):
    if wire_type == WireType.VARINT:
        return read_varint(stream)
    if wire_type == WireType.FIXED64:
        c = stream.read(FIXED64_SIZE)
        if not c or len(c) != FIXED64_SIZE:
            raise ValueError("Illegal length")
        return c
    if wire_type == WireType.LENGTH_DELIMITED:
        length = read_varint(stream)
        if length is None:
            raise ValueError("Illegal input")
        c = stream.read(length)
        if len(c) != length:
            raise ValueError("Illegal input")
        return c
    if wire_type in (WireType.START_GROUP, WireType.END_GROUP):
        return bytes(wire_type == WireType.START_GROUP)
    if wire_type == WireType.FIXED32:
        c = stream.read(FIXED32_SIZE)
        if not c or len(c) != FIXED32_SIZE:
            raise ValueError("Illegal length")
        return c
    raise ValueError("Unknown wire type %i" % wire_type)


def read_proto(stream):
    if isinstance(stream, (bytes, bytearray)):
        stream = io.BytesIO(stream)
    while True:
        tag = read_varint(stream)
        if tag is None:
            break
        wire_type = WireType(tag & 0x7)
        field_number = tag >> 3
        value = read_value(stream, wire_type)
        yield field_number, wire_type, value


def parse_proto(stream):
    # TODO: Consider converting FIXED32 and FIXED64 to int.
    return {field_number: value for field_number, _, value in read_proto(stream)}
