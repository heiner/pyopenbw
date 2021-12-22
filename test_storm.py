import struct

import pytest

import storm

# From
#   https://guidedhacking.com/threads/beginner-packet-hacking-%E2%80%93-starcraft-cheats.13626/
PACKETS = (
    ("e7 36 1e 00 01 00 05 00 01 00 01 00", b"\x00\x93This is a test.\x00"),
    ("ea 32 1e 00 02 00 05 00 01 00 01 00", b"\x00\x93This is a test.\x00"),
    ("ed 2e 1e 00 03 00 05 00 01 00 01 00", b"\x00\x93This is a test.\x00"),
    ("d5 c9 1e 00 01 00 05 00 01 00 01 00", b"\x00\x12This is a test.\x00"),
    ("c6 1a 1e 00 01 00 05 00 01 00 01 00", b"\x00\xd0This is a test.\x00"),
)


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

EVEN_MORE_PACKETS = (
    # "[Joiner sends 3 query packets] UDPPKT_JOINQUERY(0x01) S -> C"
    "28 C4 10 00 00 00 01 00 00 01 FF 00 01 00 00 00",
    # "[Host responds back] UDPPKT_HOSTQUERYRESPONSE(0x02) C -> S"
    "33 B7 10 00 01 00 01 00 00 02 00 00 01 00 00 00",
    # "[?]UDPPKT_Unknown(0x03) S -> C"
    "40 A8 10 00 01 00 02 00 00 03 FF 00 01 00 00 00",
    # "[Joiner is in the GameRoom and you gets its name and stats]
    #  UDPPKT_JOINERSINFO(0x07) S -> C"
    """1F 81 30 00 02 00 02 00 00 07 FF 00
    62 61 62 79 62 61 63 00 50 58 45 53 20 30 20 30
    20 32 36 20 30 20 30 20 30 20 30 20 30 20 50 58
    45 53 00 00""",
)

# "[Intial Creation of Game]"
CREATION = bytearray.fromhex(
    """
    FF 1C 52 00 00 00 00 00 00 00 00 00 02 00 01 00
    FF 00 00 00 00 00 00 00 34 76 34 20 48 75 6E 74
    65 72 73 00 00 2C 34 34 2C 2C 36 2C 31 2C 32 2C
    2C 31 2C 33 34 65 61 62 30 32 66 2C 34 2C 2C 74
    68 69 65 66 0D 54 68 65 20 48 75 6E 74 65 72 73
    0D 00
"""
)


class TestStorm:
    def test_subchecksum(self):
        assert storm.subchecksum(b"bbccdd") == 21551

    def test_udp_checksum(self):
        for header, payload in PACKETS:
            data = bytearray.fromhex(header) + payload
            checksum = storm.udp_checksum(data)
            assert checksum == struct.unpack("<H", data[:2])[0]
            assert struct.pack("<H", checksum) == data[:2]

    def test_udp_checksum_more(self):
        for packet in MORE_PACKETS:
            data = bytearray.fromhex(packet)
            data = data[4:]  # Strip 4 bytes of zeros.
            checksum = storm.udp_checksum(data)
            assert struct.pack("<H", checksum) == data[:2]

    def test_udp_checksum_more_yet(self):
        for packet in EVEN_MORE_PACKETS:
            data = bytearray.fromhex(packet)
            checksum = storm.udp_checksum(data)
            assert struct.pack("<H", checksum) == data[:2]

    def test_wrong_length(self):
        (header, _), *_ = PACKETS
        data = bytearray.fromhex(header)
        wrong_length = 42
        struct.pack_into("<H", data, 2, wrong_length)
        with pytest.warns(
            UserWarning,
            match=r"length %i doesn't match .* %i" % (len(data), wrong_length),
        ):
            storm.udp_checksum(data, verify=False)

    def test_read_storm_packet(self):
        sent = [1, 2, 3, 1, 1]
        recved = 5
        cls = storm.Cls.ASYNC
        cmd = 0
        player = 1
        resend = storm.Resend.NORMAL

        for header, payload in PACKETS:
            packet = bytearray.fromhex(header) + payload
            fields = storm.read_storm_packet(packet)

            assert fields[0] == sent.pop(0)
            assert fields[1] == recved
            assert fields[2] == cls
            assert fields[3] == cmd
            assert fields[4] == player
            assert fields[5] == resend
            assert fields[6] == payload

    def test_read_unclear_pkt(self, packet=CREATION):
        with pytest.raises(ValueError, match=r"Found 0x1cff but expected 0x06b8"):
            # Package unclear -- checksum is different?
            storm.read_storm_packet(packet)
        data = storm.read_storm_packet(packet, verify=False)
        for i in range(6):
            assert data[i] == 0
        assert (
            data[6]
            == b"\x02\x00\x01\x00\xff\x00\x00\x00\x00\x00\x00\x004v4 Hunters\x00\x00,44,,6,1,2,,1,34eab02f,4,,thief\rThe Hunters\r\x00"
        )

    def test_write_storm_packet(self):
        sent = [1, 2, 3, 1, 1]
        recved = 5
        cls = storm.Cls.ASYNC
        cmd = 0
        player = 1
        resend = storm.Resend.NORMAL

        for header, payload in PACKETS:
            packet_expected = bytearray.fromhex(header) + payload
            packet_written = storm.write_storm_packet(
                sent.pop(0), recved, cls, cmd, player, resend, payload
            )
            assert packet_expected == packet_written

    def test_storm_packet(self):
        for header, payload in PACKETS:
            packet = bytearray.fromhex(header) + payload
            strmpkt = storm.StormPacket.from_buffer(packet)
            assert packet == strmpkt.write()
