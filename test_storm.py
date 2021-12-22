import struct

import pytest

import storm


def hexstr2bytes(s):
    return bytes(int(h, 16) for h in s.split())


# From
#   https://guidedhacking.com/threads/beginner-packet-hacking-%E2%80%93-starcraft-cheats.13626/
HEADERS = (
    "e7 36 1e 00 01 00 05 00 01 00 01 00 00 93",
    "ea 32 1e 00 02 00 05 00 01 00 01 00 00 93",
    "ed 2e 1e 00 03 00 05 00 01 00 01 00 00 93",
    "d5 c9 1e 00 01 00 05 00 01 00 01 00 00 12",
    "c6 1a 1e 00 01 00 05 00 01 00 01 00 00 d0",
)
PAYLOAD = b"This is a test.\x00"

# From
#   https://www.darkblizz.org/Forum2/index.php?pretty;board=starcraft;topic=sc-udp-game-research.msg96#msg96
MORE_PACKETS = (
    """
    00 00 00 00 E4 72 37 00 03 00 03 00 00 06 00 00
    2B 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00
    27 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 74 68 69 65 66 00 00
    """,
    """
    00 00 00 00 19 B8 36 00 03 00 03 00 00 06 00 00
    2A 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00
    12 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 4D 79 73 74 00 00
    """,
    """
    00 00 00 00 44 27 37 00 03 00 03 00 00 06 00 00
    2B 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00
    33 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 54 68 69 65 66 00 00
    """,
)


class TestStorm:
    def test_subchecksum(self):
        assert storm.subchecksum(b"bbccdd") == 21551

    def test_udp_checksum(self):
        for header in HEADERS:
            data = hexstr2bytes(header) + PAYLOAD
            checksum = storm.udp_checksum(data[2:])
            assert checksum == struct.unpack("<H", data[:2])[0]
            assert struct.pack("<H", checksum) == data[:2]

    def test_udp_checksum_more(self):
        for packet in MORE_PACKETS:
            data = hexstr2bytes(packet)
            data = data[4:]  # Strip 4 bytes of zeros.
            checksum = storm.udp_checksum(data[2:])
            assert struct.pack("<H", checksum) == data[:2]

    def test_wrong_length(self):
        header, *_ = HEADERS
        data = hexstr2bytes(header)
        wrong_length = 42
        data = struct.pack("<H", wrong_length) + data[4:]
        with pytest.raises(
            ValueError, match=r"length %i doesn't match .* %i" % (len(data), 40)
        ):
            storm.udp_checksum(data)
