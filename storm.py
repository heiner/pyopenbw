import dataclasses
import enum
import struct
import warnings


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
        sum2 %= 0xFF
        sum1 += sum2
    return ((sum2 & 0xFF) << 8) | ((sum1 % 0xFF) & 0xFF)


def udp_checksum(buf, verify=True):
    length, *_ = struct.unpack("<H", buf[2:4])
    if length != len(buf):
        warnings.warn(
            "Buffer of length %i doesn't match its length entry %i" % (len(buf), length)
        )
    subsum = subchecksum(buf[2:length])
    a = 0xFF - ((subsum & 0xFF) + (subsum >> 8)) % 0xFF
    b = (((0xFF - (a + (subsum >> 8))) % 0xFF) & 0xFF) | (a << 8)
    checksum = b & 0xFFFF
    if verify:
        value, *_ = struct.unpack("<H", buf[:2])
        if value != checksum:
            raise ValueError(
                "Checksum mismatch: Found 0x%04x but expected 0x%04x"
                % (value, checksum)
            )
    return checksum


def read_storm_packet(buf, verify=True):
    checksum, length, sent, recved, cls, cmd, player, resend = struct.unpack(
        "<HHHHbbbb", buf[:12]
    )
    buf = buf[:length]
    if verify:
        udp_checksum(buf)
        try:
            cls = Cls(cls)
        except ValueError:
            pass
        if cls != Cls.INTERNAL and cmd != 0:
            raise ValueError("Found cmd of %i but should be 0 for cls %r" % (cmd, cls))
    return sent, recved, cls, cmd, player, resend, buf[12:]


def write_storm_packet(sent, recved, cls, cmd, player, resend, payload):
    if cls != Cls.INTERNAL and cmd != 0:
        raise ValueError("Found cmd of %i but should be 0 for cls %s" % (cmd, cls))

    packet = bytearray(12 + len(payload))
    struct.pack_into(
        "<HHHHbbbb",
        packet,
        0,  # Offset.
        0,  # Null checksum.
        len(packet),
        sent,
        recved,
        cls,
        cmd,
        player,
        resend,
    )
    packet[12:] = payload
    struct.pack_into("<H", packet, 0, udp_checksum(packet, verify=False))
    return packet


@dataclasses.dataclass
class StormPacket:
    sent: int
    recved: int
    cls: Cls
    cmd: int
    player: int
    resend: Resend
    payload: bytes

    def write(self):
        return write_storm_packet(**dataclasses.asdict(self))

    @classmethod
    def from_buffer(cls, buf):
        return StormPacket(*read_storm_packet(buf))
