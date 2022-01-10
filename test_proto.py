import proto

EXAMPLES = [
    bytes.fromhex(data)
    for data in (
        """08 01 12 3f 00 00 00 00 65 35 3b 00 0b 00 04 00 01 00 00 00 00 9a 71
        71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71
        71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 00 28 94 8c 86
        be d0 af 89 e8 b3 01 5a 00""",
        """08 01 12 17 00 00 00 00 f5 dd 13 00 90 67 8f 67 02 00 01 00 37 32 e4
        36 47 4c 0f 28 d6 e2 a8 ca 8e de d4 93 5d 5a 00""",
        """08 01 12 17 00 00 00 00 eb 23 13 00 8f 67 90 67 02 00 00 00 37 21 0f
        6a 05 06 10 28 ef d7 d7 81 c2 a8 ac 9b df 01 5a 00""",
    )
]

PARSED_EXAMPLES = (
    [
        (1, proto.WireType.VARINT, 1),
        (2, proto.WireType.LENGTH_DELIMITED, EXAMPLES[0][4:-13]),
        (5, proto.WireType.VARINT, 12956897346876179988),
        (11, proto.WireType.LENGTH_DELIMITED, b""),
    ],
    [
        (1, proto.WireType.VARINT, 1),
        (2, proto.WireType.LENGTH_DELIMITED, EXAMPLES[1][4:-12]),
        (5, proto.WireType.VARINT, 6712424964278595926),
        (11, proto.WireType.LENGTH_DELIMITED, b""),
    ],
    [
        (1, proto.WireType.VARINT, 1),
        (2, proto.WireType.LENGTH_DELIMITED, EXAMPLES[2][4:-13]),
        (5, proto.WireType.VARINT, 16084238025356602351),
        (11, proto.WireType.LENGTH_DELIMITED, b""),
    ],
)


class TestProto:
    def test_read_examples(self):
        for example, parsed_example in zip(EXAMPLES, PARSED_EXAMPLES):
            parsed = list(proto.read_proto(example))
            assert len(parsed_example) == len(parsed)
            for lhs, rhs in zip(parsed_example, parsed):
                assert len(rhs) == 3
                for i in range(3):  # field_number, wire_type, value.
                    assert lhs[i] == rhs[i]

    def test_parse_examples(self):
        for example, parsed_example in zip(EXAMPLES, PARSED_EXAMPLES):
            parsed_example = {fn: v for fn, _, v in parsed_example}
            assert parsed_example == proto.parse_proto(example)
