pub const DerSignature = struct {
    bytes: []const u8,
};

pub const TxSignature = struct {
    der: []const u8,
    sighash_type: u8,
};
