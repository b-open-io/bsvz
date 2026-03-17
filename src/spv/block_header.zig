pub const BlockHeader = struct {
    version: i32,
    prev_block: [32]u8,
    merkle_root: [32]u8,
    timestamp: u32,
    bits: u32,
    nonce: u32,
};
