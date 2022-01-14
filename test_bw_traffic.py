import base64
import csv
import enum

import proto
import storm


class PB(enum.IntEnum):
    ALWAYS_ONE = 1
    STORM_PACKET = 2
    SOMETIMES_ZERO = 3  # Seldom present.
    SOMETIMES_ALSO_ZERO = 4  # Shows up with 3.
    CHECKSUM = 5
    NINE_VARINT = 9  # Shows up with when 11 is nonempty.
    OFTEN_EMPTY = 11  # Not always, present with 3.
    SOMETIMES_9 = 12  # Shows up with 3.


class TestBWData:
    def test_traffic_data(self):
        no_storm_packet = 0
        packet_with_nine = 0

        print("")

        with open("traffic_data.tsv") as f:
            reader = csv.DictReader(f, delimiter="\t")
            for i, row in enumerate(reader):  # noqa: B007
                data = base64.b64decode(row["data"])
                pb = proto.parse_proto(data)

                assert pb[PB.ALWAYS_ONE] == 1

                if PB.NINE_VARINT in pb:
                    # This is some kind of request/response. In this
                    # data it shows up 64 times, half with a storm packet
                    # and half without.
                    packet_with_nine += 1
                    assert pb[PB.OFTEN_EMPTY]
                    assert 0x5D3C2A == pb[PB.NINE_VARINT] >> 28
                    # print("0x%x" % pb[PB.NINE_VARINT], pb[PB.OFTEN_EMPTY])
                    # print(row["peer"], pb)

                if pb[PB.OFTEN_EMPTY]:
                    assert PB.NINE_VARINT in pb

                if PB.STORM_PACKET in pb:
                    # Raises error if checksum is wrong.
                    strm = storm.StormPacket.from_buffer(
                        pb[PB.STORM_PACKET], verify=True
                    )

                    assert strm.player == (int(row["peer"]) + 1) % 2

                    assert PB.SOMETIMES_ZERO not in pb
                    assert PB.SOMETIMES_ALSO_ZERO not in pb
                    assert PB.CHECKSUM in pb

                    if PB.NINE_VARINT in pb:
                        # This is typically not the case.
                        assert pb[PB.OFTEN_EMPTY]
                    else:
                        # This is the typical case.
                        assert not pb[PB.OFTEN_EMPTY]
                    assert PB.SOMETIMES_9 not in pb

                    continue

                # No storm packet data in proto.
                no_storm_packet += 1
                assert PB.SOMETIMES_ZERO in pb
                assert PB.SOMETIMES_ALSO_ZERO in pb
                assert PB.NINE_VARINT in pb
                assert pb[PB.OFTEN_EMPTY]  # Not empty in this case.
                assert pb[PB.SOMETIMES_9] == 9

        print(
            "Read %i packets, %i w/o storm data, %i with pb key 9"
            % (i, no_storm_packet, packet_with_nine)
        )
