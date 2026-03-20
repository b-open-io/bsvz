const crypto = @import("../crypto/lib.zig");

pub fn MerkleTreeParent(left: crypto.Hash256, right: crypto.Hash256) crypto.Hash256 {
    var concat: [64]u8 = undefined;
    @memcpy(concat[0..32], &left.bytes);
    @memcpy(concat[32..64], &right.bytes);
    return crypto.hash.hash256(&concat);
}
