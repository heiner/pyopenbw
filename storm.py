import enum
import struct


class Cls(enum.IntEnum):
    """Command class."""

    INTERNAL = 0
    ASYNC = 1
    SYNC = 2


class Resend(enum.IntEnum):
    NORMAL = 0
    VERIFY = 1  # Used to verify Seq1 (send) and Seq2 (recved).
    RESEND = 2  # Resend request.
    CALLBACK = 3  # Resend response.


EVERYONE = 0xFF  # Player id for "all".


def subchecksum(buf):
    sum1, sum2 = 0, 0
    for ch in reversed(buf):
        sum2 += ch
        if sum2 > 0xFF:
            sum2 -= 0xFF
        sum1 += sum2
    return ((sum2 & 0xFF) << 8) | ((sum1 % 0xFF) & 0xFF)


def udp_checksum(buf):
    length, *_ = struct.unpack("<H", buf[:2])
    if length - 2 != len(buf):
        raise ValueError(
            "Buffer of length %i doesn't match its adjusted length entry of %i"
            % (len(buf), length - 2)
        )
    subsum = subchecksum(buf)
    a = 0xFF - ((subsum & 0xFF) + (subsum >> 8)) % 0xFF
    b = (((0xFF - (a + (subsum >> 8))) % 0xFF) & 0xFF) | (a << 8)
    return b & 0xFFFF


def read_storm_packet(buf, verify=True):
    checksum, length, sent, recved, cls, cmd, player, resend = struct.unpack(
        "<HHHHbbbb", buf[:12]
    )
    if verify and checksum != udp_checksum(buf[2:]):
        raise ValueError(
            "Checksum mismatch: Found 0x%04x but expected 0x%04x"
            % (checksum, udp_checksum(buf[2:]))
        )
    if verify and cls != Cls.INTERNAL and cmd != 0:
        raise ValueError(
            "Found cmd of %i but should be 0 for cls %s" % (cmd, Cls.value(cls))
        )
    return sent, recved, cls, cmd, player, resend, buf[12:]