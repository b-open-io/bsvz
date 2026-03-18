const std = @import("std");
const crypto = @import("../crypto/lib.zig");
const primitives = @import("../primitives/lib.zig");
const script = @import("../script/lib.zig");

pub const Error = error{
    InvalidAddressPayload,
    InvalidNetworkPrefix,
};

pub const P2pkhAddress = struct {
    network: primitives.network.Network,
    pubkey_hash: crypto.Hash160,

    pub fn encode(self: P2pkhAddress, allocator: std.mem.Allocator) ![]u8 {
        var payload: [21]u8 = undefined;
        payload[0] = self.network.p2pkhPrefix();
        @memcpy(payload[1..], &self.pubkey_hash.bytes);
        return primitives.base58.encodeCheck(allocator, &payload);
    }

    pub fn lockingScript(self: P2pkhAddress) [script.templates.p2pkh.locking_script_len]u8 {
        return script.templates.p2pkh.encode(self.pubkey_hash);
    }
};

pub fn encodeP2pkh(
    allocator: std.mem.Allocator,
    network: primitives.network.Network,
    pubkey_hash: crypto.Hash160,
) ![]u8 {
    return (P2pkhAddress{
        .network = network,
        .pubkey_hash = pubkey_hash,
    }).encode(allocator);
}

pub fn encodeP2pkhFromPublicKey(
    allocator: std.mem.Allocator,
    network: primitives.network.Network,
    public_key: crypto.PublicKey,
) ![]u8 {
    return encodeP2pkh(allocator, network, crypto.hash.hash160(&public_key.bytes));
}

pub fn decodeP2pkh(allocator: std.mem.Allocator, address: []const u8) !P2pkhAddress {
    const payload = try primitives.base58.decodeCheck(allocator, address);
    defer allocator.free(payload);

    if (payload.len != 21) return error.InvalidAddressPayload;

    return .{
        .network = networkFromPrefix(payload[0]) orelse return error.InvalidNetworkPrefix,
        .pubkey_hash = .{ .bytes = payload[1..21].* },
    };
}

fn networkFromPrefix(prefix: u8) ?primitives.network.Network {
    return switch (prefix) {
        0x00 => .mainnet,
        0x6f => .testnet,
        else => null,
    };
}

test "p2pkh address encodes the all-zero mainnet vector" {
    const allocator = std.testing.allocator;
    const address = try encodeP2pkh(
        allocator,
        .mainnet,
        .{ .bytes = [_]u8{0} ** 20 },
    );
    defer allocator.free(address);

    try std.testing.expectEqualSlices(u8, "1111111111111111111114oLvT2", address);
}

test "p2pkh address decode roundtrip preserves network and locking script" {
    const allocator = std.testing.allocator;
    const original = P2pkhAddress{
        .network = .testnet,
        .pubkey_hash = .{ .bytes = [_]u8{0x42} ** 20 },
    };

    const encoded = try original.encode(allocator);
    defer allocator.free(encoded);

    const decoded = try decodeP2pkh(allocator, encoded);
    const original_locking_script = original.lockingScript();
    const decoded_locking_script = decoded.lockingScript();
    try std.testing.expectEqual(original.network, decoded.network);
    try std.testing.expectEqual(original.pubkey_hash, decoded.pubkey_hash);
    try std.testing.expectEqualSlices(u8, &original_locking_script, &decoded_locking_script);
}

test "p2pkh address from compressed public key one matches the known vector" {
    const allocator = std.testing.allocator;
    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 1;

    const private_key = try crypto.PrivateKey.fromBytes(key_bytes);
    const public_key = try private_key.publicKey();
    const address = try encodeP2pkhFromPublicKey(allocator, .mainnet, public_key);
    defer allocator.free(address);

    try std.testing.expectEqualSlices(u8, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", address);
}

test "p2pkh address decode rejects malformed payloads and prefixes" {
    const allocator = std.testing.allocator;

    const short_payload = try primitives.base58.encodeCheck(allocator, &([_]u8{0x00} ++ ([_]u8{0x11} ** 19)));
    defer allocator.free(short_payload);
    try std.testing.expectError(error.InvalidAddressPayload, decodeP2pkh(allocator, short_payload));

    const bad_prefix = try primitives.base58.encodeCheck(allocator, &([_]u8{0x05} ++ ([_]u8{0x22} ** 20)));
    defer allocator.free(bad_prefix);
    try std.testing.expectError(error.InvalidNetworkPrefix, decodeP2pkh(allocator, bad_prefix));

    try std.testing.expectError(error.InvalidChecksum, decodeP2pkh(allocator, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAM2"));
}
