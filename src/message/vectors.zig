//! Cross-runtime fixtures from `scripts/gen_message_vectors` (go-sdk-accurate wire).
const std = @import("std");
const ec = @import("../primitives/ec.zig");
const signed = @import("signed.zig");
const encrypted = @import("encrypted.zig");

const fixture_json = @embedFile("fixtures/message_vectors.json");

const Doc = struct {
    brc77: []B77,
    brc78: []B78,
};

const B77 = struct {
    case: []const u8,
    message_hex: []const u8,
    sender_priv_hex: []const u8,
    recipient_priv_hex: ?[]const u8 = null,
    anyone: bool,
    key_id_hex: []const u8,
    signature_hex: []const u8,
    expected_invoice_suffix_b64: ?[]const u8 = null,
};

const B78 = struct {
    case: []const u8,
    plaintext_hex: []const u8,
    sender_priv_hex: []const u8,
    recipient_priv_hex: []const u8,
    key_id_hex: []const u8,
    ciphertext_hex: []const u8,
};

fn hexPriv(hex_str: []const u8) !ec.PrivateKey {
    var b: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&b, hex_str);
    return ec.PrivateKey.fromBytes(b);
}

fn hexBytes(allocator: std.mem.Allocator, hex_str: []const u8) ![]u8 {
    if (hex_str.len == 0) return try allocator.alloc(u8, 0);
    const n = hex_str.len / 2;
    const buf = try allocator.alloc(u8, n);
    _ = try std.fmt.hexToBytes(buf, hex_str);
    return buf;
}

test "go-sdk message vectors (BRC-77 + BRC-78)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const parsed = try std.json.parseFromSlice(Doc, a, fixture_json, .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();
    const d = parsed.value;

    for (d.brc77) |row| {
        const msg = try hexBytes(a, row.message_hex);
        var kid: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&kid, row.key_id_hex);
        const sender = try hexPriv(row.sender_priv_hex);
        const want_sig = try hexBytes(a, row.signature_hex);

        if (row.expected_invoice_suffix_b64) |sfx| {
            var b64b: [48]u8 = undefined;
            const enc = std.base64.standard.Encoder.encode(&b64b, &kid);
            try std.testing.expectEqualStrings(sfx, enc);
        }

        if (row.anyone) {
            try std.testing.expect(try signed.verify(msg, want_sig, null));
            const zig_sig = try signed.signAllocWithKeyId(std.testing.allocator, msg, sender, null, kid);
            defer std.testing.allocator.free(zig_sig);
            try std.testing.expect(try signed.verify(msg, zig_sig, null));
        } else {
            const rp = try hexPriv(row.recipient_priv_hex.?);
            const rpub = try rp.publicKey();
            try std.testing.expect(try signed.verify(msg, want_sig, rp));
            const zig_sig = try signed.signAllocWithKeyId(std.testing.allocator, msg, sender, rpub, kid);
            defer std.testing.allocator.free(zig_sig);
            try std.testing.expect(try signed.verify(msg, zig_sig, rp));
        }
    }

    for (d.brc78) |row| {
        const pt: []const u8 = if (row.plaintext_hex.len == 0)
            &[_]u8{}
        else
            try hexBytes(a, row.plaintext_hex);
        const rp = try hexPriv(row.recipient_priv_hex);
        const ct = try hexBytes(a, row.ciphertext_hex);
        const dec = try encrypted.decryptAlloc(std.testing.allocator, ct, rp);
        defer std.testing.allocator.free(dec);
        try std.testing.expectEqualSlices(u8, pt, dec);
    }
}
