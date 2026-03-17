const std = @import("std");

pub const Hash160 = struct {
    bytes: [20]u8,

    pub fn eql(self: Hash160, other: Hash160) bool {
        return std.mem.eql(u8, &self.bytes, &other.bytes);
    }
};

pub const Hash256 = struct {
    bytes: [32]u8,

    pub fn zero() Hash256 {
        return .{ .bytes = [_]u8{0} ** 32 };
    }

    pub fn eql(self: Hash256, other: Hash256) bool {
        return std.mem.eql(u8, &self.bytes, &other.bytes);
    }
};

pub fn sha256(data: []const u8) Hash256 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &out, .{});
    return .{ .bytes = out };
}

pub fn hash256(data: []const u8) Hash256 {
    const first = sha256(data);
    return sha256(&first.bytes);
}

test "sha256 returns a non-zero digest for non-empty data" {
    const digest = sha256("bsvz");
    try std.testing.expect(!digest.eql(Hash256.zero()));
}
