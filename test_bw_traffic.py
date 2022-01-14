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
    OTHER_CHECKSUM = 9  # Shows up with when 11 is nonempty.
    OFTEN_EMPTY = 11  # Not always, present with 3.
    SOMETIMES_9 = 12  # Shows up with 3.


class TestBWData:
    def test_traffic_data(self):
        no_storm_packet = 0

        with open("traffic_data.tsv") as f:
            reader = csv.DictReader(f, delimiter="\t")
            for i, row in enumerate(reader):  # noqa: B007
                data = base64.b64decode(row["data"])
                pb = proto.parse_proto(data)

                assert pb[PB.ALWAYS_ONE] == 1

                if PB.STORM_PACKET in pb:
                    # Raises error if checksum is wrong.
                    strm = storm.StormPacket.from_buffer(
                        pb[PB.STORM_PACKET], verify=True
                    )

                    assert strm.player == (int(row["peer"]) + 1) % 2

                    assert PB.SOMETIMES_ZERO not in pb
                    assert PB.SOMETIMES_ALSO_ZERO not in pb

                    if PB.OTHER_CHECKSUM in pb:
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
                assert PB.OTHER_CHECKSUM in pb
                assert pb[PB.OFTEN_EMPTY]  # Not empty in this case.
                assert pb[PB.SOMETIMES_9] == 9

        print("Read %i packets, %i w/o storm data" % (i, no_storm_packet))
