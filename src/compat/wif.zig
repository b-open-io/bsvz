const std = @import("std");
const crypto = @import("../crypto/lib.zig");
const primitives = @import("../primitives/lib.zig");

pub const Error = error{
    InvalidWifPayload,
    InvalidNetworkPrefix,
};

pub const Wif = struct {
    network: primitives.network.Network,
    private_key: crypto.PrivateKey,
    compressed: bool,

    pub fn encode(self: Wif, allocator: std.mem.Allocator) ![]u8 {
        const payload_len: usize = if (self.compressed) 34 else 33;
        var payload: [34]u8 = undefined;
        payload[0] = self.network.wifPrefix();
        payload[1..33].* = self.private_key.toBytes();
        if (self.compressed) payload[33] = 0x01;
        return primitives.base58.encodeCheck(allocator, payload[0..payload_len]);
    }
};

pub fn encode(
    allocator: std.mem.Allocator,
    network: primitives.network.Network,
    private_key: crypto.PrivateKey,
    compressed: bool,
) ![]u8 {
    return (Wif{
        .network = network,
        .private_key = private_key,
        .compressed = compressed,
    }).encode(allocator);
}

pub fn decode(allocator: std.mem.Allocator, text: []const u8) !Wif {
    const payload = try primitives.base58.decodeCheck(allocator, text);
    defer allocator.free(payload);

    if (payload.len != 33 and payload.len != 34) return error.InvalidWifPayload;
    if (payload.len == 34 and payload[33] != 0x01) return error.InvalidWifPayload;

    return .{
        .network = networkFromPrefix(payload[0]) orelse return error.InvalidNetworkPrefix,
        .private_key = try crypto.PrivateKey.fromBytes(payload[1..33].*),
        .compressed = payload.len == 34,
    };
}

fn networkFromPrefix(prefix: u8) ?primitives.network.Network {
    return switch (prefix) {
        0x80 => .mainnet,
        0xef => .testnet,
        else => null,
    };
}

test "wif compressed mainnet key one matches the known vector" {
    const allocator = std.testing.allocator;
    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 1;

    const private_key = try crypto.PrivateKey.fromBytes(key_bytes);
    const encoded = try encode(
        allocator,
        .mainnet,
        private_key,
        true,
    );
    defer allocator.free(encoded);

    try std.testing.expectEqualSlices(u8, "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn", encoded);

    const decoded = try decode(allocator, encoded);
    try std.testing.expectEqual(primitives.network.Network.mainnet, decoded.network);
    try std.testing.expectEqual(true, decoded.compressed);
    try std.testing.expectEqual(key_bytes, decoded.private_key.toBytes());
}

test "wif decode roundtrip preserves key bytes and compression flag" {
    const allocator = std.testing.allocator;
    var key_bytes = [_]u8{0x42} ** 32;
    key_bytes[0] = 0x01;

    const private_key = try crypto.PrivateKey.fromBytes(key_bytes);
    const encoded = try encode(allocator, .testnet, private_key, false);
    defer allocator.free(encoded);

    const decoded = try decode(allocator, encoded);
    try std.testing.expectEqual(primitives.network.Network.testnet, decoded.network);
    try std.testing.expectEqual(false, decoded.compressed);
    try std.testing.expectEqual(key_bytes, decoded.private_key.toBytes());
}

test "wif decode rejects malformed payloads, prefixes, and checksums" {
    const allocator = std.testing.allocator;
    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 1;

    const short_payload = try primitives.base58.encodeCheck(allocator, &([_]u8{0x80} ++ ([_]u8{0x00} ** 31)));
    defer allocator.free(short_payload);
    try std.testing.expectError(error.InvalidWifPayload, decode(allocator, short_payload));

    const bad_suffix_payload = try primitives.base58.encodeCheck(allocator, &([_]u8{0x80} ++ key_bytes ++ [_]u8{0x02}));
    defer allocator.free(bad_suffix_payload);
    try std.testing.expectError(error.InvalidWifPayload, decode(allocator, bad_suffix_payload));

    const bad_prefix = try primitives.base58.encodeCheck(allocator, &([_]u8{0x81} ++ key_bytes));
    defer allocator.free(bad_prefix);
    try std.testing.expectError(error.InvalidNetworkPrefix, decode(allocator, bad_prefix));

    try std.testing.expectError(error.InvalidChecksum, decode(allocator, "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWa"));
}
