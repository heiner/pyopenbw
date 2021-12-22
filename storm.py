import struct


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
