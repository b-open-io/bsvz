pub const Opcode = enum(u8) {
    OP_0 = 0x00,
    OP_DUP = 0x76,
    OP_HASH160 = 0xa9,
    OP_EQUALVERIFY = 0x88,
    OP_CHECKSIG = 0xac,
    OP_RETURN = 0x6a,
};
