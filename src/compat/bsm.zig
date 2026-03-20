//! Bitcoin Signed Message (BIP-ish / Bitcoin Core style). Matches go-sdk `compat/bsm`.
const std = @import("std");
const primitives = @import("../primitives/lib.zig");
const crypto = @import("../crypto/lib.zig");
const address = @import("address.zig");

pub const h_bsv = "Bitcoin Signed Message:\n";

pub const Error = error{
    AddressMismatch,
};

fn appendPayload(list: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, message: []const u8) !void {
    var vi_buf: [9]u8 = undefined;
    const hlen = try primitives.varint.VarInt.encodeInto(&vi_buf, h_bsv.len);
    try list.appendSlice(allocator, vi_buf[0..hlen]);
    try list.appendSlice(allocator, h_bsv);
    const mlen = try primitives.varint.VarInt.encodeInto(&vi_buf, message.len);
    try list.appendSlice(allocator, vi_buf[0..mlen]);
    try list.appendSlice(allocator, message);
}

/// Double-SHA256 of the BSM-prefixed payload (`VarInt(len) || prefix || VarInt(len) || message`).
pub fn messageDigestAlloc(allocator: std.mem.Allocator, message: []const u8) ![32]u8 {
    var list = std.ArrayListUnmanaged(u8){};
    errdefer list.deinit(allocator);
    try appendPayload(&list, allocator, message);
    const owned = try list.toOwnedSlice(allocator);
    defer allocator.free(owned);
    return crypto.hash.hash256(owned).bytes;
}

/// Sign message; compact signature references compressed pubkey by default (Go `SignMessage`).
pub fn signMessage(key: crypto.PrivateKey, message: []const u8, allocator: std.mem.Allocator) ![crypto.compact_sig_len]u8 {
    return signMessageWithCompression(key, message, allocator, true);
}

pub fn signMessageWithCompression(
    key: crypto.PrivateKey,
    message: []const u8,
    allocator: std.mem.Allocator,
    sig_ref_compressed_key: bool,
) ![crypto.compact_sig_len]u8 {
    const d = try messageDigestAlloc(allocator, message);
    return crypto.signCompactDigest256(key, d, sig_ref_compressed_key);
}

pub fn recoverPubkey(
    sig65: [crypto.compact_sig_len]u8,
    message: []const u8,
    allocator: std.mem.Allocator,
) !crypto.RecoveredPubkey {
    const d = try messageDigestAlloc(allocator, message);
    return crypto.recoverCompactDigest256(sig65, d);
}

/// Compare P2PKH address string (base58check) to pubkey implied by the signature.
pub fn verifyMessage(
    allocator: std.mem.Allocator,
    network: primitives.network.Network,
    address_str: []const u8,
    sig65: [crypto.compact_sig_len]u8,
    message: []const u8,
) !void {
    const rec = try recoverPubkey(sig65, message, allocator);
    const expected = try address.encodeP2pkhFromPublicKey(allocator, network, rec.pubkey);
    defer allocator.free(expected);
    if (!std.mem.eql(u8, expected, address_str)) return error.AddressMismatch;
}

test "bsm sign / recover / verify roundtrip" {
    const allocator = std.testing.allocator;
    var kb: [32]u8 = [_]u8{0} ** 32;
    kb[31] = 1;
    const sk = try crypto.PrivateKey.fromBytes(kb);
    const message = "hello bsm";
    const sig = try signMessage(sk, message, allocator);
    const rec = try recoverPubkey(sig, message, allocator);
    const pk = try sk.publicKey();
    try std.testing.expectEqualSlices(u8, &pk.bytes, &rec.pubkey.bytes);
    try std.testing.expect(rec.is_compressed);

    const addr = try address.encodeP2pkhFromPublicKey(allocator, .mainnet, pk);
    defer allocator.free(addr);
    try verifyMessage(allocator, .mainnet, addr, sig, message);
}
