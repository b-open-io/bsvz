pub const SigHashType = enum(u8) {
    all = 0x01,
    none = 0x02,
    single = 0x03,
    anyone_can_pay = 0x80,
};
