import struct

import storm


def hexstr2bytes(s):
    return bytes(int(h, 16) for h in s.split())


HEADERS = (
    "e7 36 1e 00 01 00 05 00 01 00 01 00 00 93",
    "ea 32 1e 00 02 00 05 00 01 00 01 00 00 93",
    "ed 2e 1e 00 03 00 05 00 01 00 01 00 00 93",
    "d5 c9 1e 00 01 00 05 00 01 00 01 00 00 12",
    "c6 1a 1e 00 01 00 05 00 01 00 01 00 00 d0",
)
PAYLOAD = b"This is a test.\x00"


class TestStorm:
    def test_subchecksum(self):
        assert storm.subchecksum(b"bbccdd") == 21551

    def test_udp_checksum(self):
        for header in HEADERS:
            data = hexstr2bytes(header) + PAYLOAD
            checksum = storm.udp_checksum(data[2:])
            assert checksum == struct.unpack("<H", data[:2])[0]
            assert struct.pack("<H", checksum) == data[:2]
