const std = @import("std");
const crypto = @import("../../crypto/lib.zig");
const primitives = @import("../../primitives/lib.zig");
const opcode = @import("../opcode.zig").Opcode;

pub const locking_script_len: usize = 25;

pub fn encode(pubkey_hash: crypto.Hash160) [locking_script_len]u8 {
    var out: [locking_script_len]u8 = undefined;
    out[0] = @intFromEnum(opcode.OP_DUP);
    out[1] = @intFromEnum(opcode.OP_HASH160);
    out[2] = 0x14;
    @memcpy(out[3..23], &pubkey_hash.bytes);
    out[23] = @intFromEnum(opcode.OP_EQUALVERIFY);
    out[24] = @intFromEnum(opcode.OP_CHECKSIG);
    return out;
}

pub fn matches(locking_script: []const u8) bool {
    return locking_script.len == locking_script_len and
        locking_script[0] == @intFromEnum(opcode.OP_DUP) and
        locking_script[1] == @intFromEnum(opcode.OP_HASH160) and
        locking_script[2] == 0x14 and
        locking_script[23] == @intFromEnum(opcode.OP_EQUALVERIFY) and
        locking_script[24] == @intFromEnum(opcode.OP_CHECKSIG);
}

pub fn extractPubKeyHash(locking_script: []const u8) !crypto.Hash160 {
    if (!matches(locking_script)) return error.InvalidScriptTemplate;
    return .{ .bytes = locking_script[3..23].* };
}

test "p2pkh encode and extract roundtrip" {
    const pubkey_hash = crypto.Hash160{ .bytes = [_]u8{0x42} ** 20 };
    const locking_script = encode(pubkey_hash);

    try std.testing.expect(matches(&locking_script));
    try std.testing.expectEqual(pubkey_hash, try extractPubKeyHash(&locking_script));
}

test "p2pkh match rejects malformed scripts" {
    try std.testing.expect(!matches(&[_]u8{}));
    try std.testing.expect(!matches(&[_]u8{ 0x76, 0xa9, 0x13 }));
}

test "p2pkh matches the canonical key-one vector across layers" {
    const allocator = std.testing.allocator;
    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 1;

    const expected_pubkey_hash_bytes = try primitives.hex.decode(
        allocator,
        "751e76e8199196d454941c45d1b3a323f1433bd6",
    );
    defer allocator.free(expected_pubkey_hash_bytes);
    const expected_locking_script = try primitives.hex.decode(
        allocator,
        "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac",
    );
    defer allocator.free(expected_locking_script);

    const private_key = try crypto.PrivateKey.fromBytes(key_bytes);
    const public_key = try private_key.publicKey();
    const pubkey_hash = crypto.hash.hash160(&public_key.bytes);
    const locking_script = encode(pubkey_hash);
    const address_payload = [_]u8{0x00} ++ pubkey_hash.bytes;
    const address = try primitives.base58.encodeCheck(allocator, &address_payload);
    defer allocator.free(address);

    try std.testing.expectEqualSlices(u8, expected_pubkey_hash_bytes, &pubkey_hash.bytes);
    try std.testing.expectEqualSlices(u8, expected_locking_script, &locking_script);
    try std.testing.expectEqualSlices(u8, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", address);
}

test "p2pkh extract rejects near-miss scripts" {
    var bad_push = encode(.{ .bytes = [_]u8{0x11} ** 20 });
    bad_push[2] = 0x13;
    try std.testing.expectError(error.InvalidScriptTemplate, extractPubKeyHash(&bad_push));

    var bad_opcode = encode(.{ .bytes = [_]u8{0x22} ** 20 });
    bad_opcode[23] = 0x87;
    try std.testing.expectError(error.InvalidScriptTemplate, extractPubKeyHash(&bad_opcode));

    var truncated = encode(.{ .bytes = [_]u8{0x33} ** 20 });
    try std.testing.expectError(error.InvalidScriptTemplate, extractPubKeyHash(truncated[0 .. truncated.len - 1]));
}
