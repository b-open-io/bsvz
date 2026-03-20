//! BRC-43 invoice numbers for wallet key derivation: `<securityLevel>-<protocolID>-<keyID>`.
//! Matches `go-sdk/wallet/key_deriver.go` `computeInvoiceNumber` and `ts-sdk` `KeyDeriver.computeInvoiceNumber`.
//! https://bsv.brc.dev/key-derivation/0043 — feed the result into `primitives.ec` `deriveChild` as UTF-8 bytes.
const std = @import("std");

/// Max length for normal protocol names (Go/TS wallet).
pub const protocol_name_max = 400;
/// When protocol starts with this prefix, max length is 430 (specific linkage revelation flows).
pub const linkage_prefix = "specific linkage revelation ";
pub const protocol_name_max_linkage = 430;
/// Key ID max length (Go `wallet`, TS `KeyDeriver`).
pub const key_id_max = 800;

/// Go `wallet.Protocol` / TS `WalletProtocol` tuple.
pub const Protocol = struct {
    /// Must be 0, 1, or 2 (`formatInvoice` validates).
    security: u8,
    name: []const u8,
};

pub const Error = error{
    InvalidSecurityLevel,
    InvalidProtocolCharacter,
    ProtocolIdTooShort,
    ProtocolNameTooLong,
    ProtocolLinkageTooLong,
    InvalidProtocolSuffix,
    ProtocolDoubleSpace,
    InvalidKeyId,
    KeyIdTooLong,
    BufferTooSmall,
} || std.mem.Allocator.Error;

/// Validates and normalizes protocol name: ASCII trim, ASCII lower case, no `  `, `[a-z0-9 ]+`, length rules.
/// `out.len` must be at least `trimmed` length (at most `protocol_name_max_linkage`).
pub fn normalizeProtocolId(protocol: []const u8, out: []u8) Error!usize {
    const trimmed = std.mem.trim(u8, protocol, &std.ascii.whitespace);
    if (trimmed.len < 5) return error.ProtocolIdTooShort;
    if (trimmed.len > protocol_name_max) {
        if (std.mem.startsWith(u8, trimmed, linkage_prefix)) {
            if (trimmed.len > protocol_name_max_linkage) return error.ProtocolLinkageTooLong;
        } else {
            return error.ProtocolNameTooLong;
        }
    }
    if (out.len < trimmed.len) return error.BufferTooSmall;

    var w: usize = 0;
    for (trimmed) |c| {
        const b: u8 = switch (c) {
            'A'...'Z' => c + 32,
            'a'...'z', '0'...'9', ' ' => c,
            else => return error.InvalidProtocolCharacter,
        };
        if (w > 0 and out[w - 1] == ' ' and b == ' ') return error.ProtocolDoubleSpace;
        out[w] = b;
        w += 1;
    }

    if (w >= 9 and std.mem.eql(u8, out[w - 9 .. w], " protocol")) return error.InvalidProtocolSuffix;
    return w;
}

/// Same rules as Go `KeyDeriver.computeInvoiceNumber` / wallet wire helpers.
pub fn formatInvoice(
    allocator: std.mem.Allocator,
    security: u8,
    protocol_id: []const u8,
    key_id: []const u8,
) Error![]u8 {
    if (security > 2) return error.InvalidSecurityLevel;
    if (key_id.len == 0) return error.InvalidKeyId;
    if (key_id.len > key_id_max) return error.KeyIdTooLong;

    var norm: [protocol_name_max_linkage]u8 = undefined;
    const n = try normalizeProtocolId(protocol_id, &norm);
    return try std.fmt.allocPrint(allocator, "{d}-{s}-{s}", .{
        security,
        norm[0..n],
        key_id,
    });
}

pub fn formatInvoiceProtocol(allocator: std.mem.Allocator, protocol: Protocol, key_id: []const u8) Error![]u8 {
    return formatInvoice(allocator, protocol.security, protocol.name, key_id);
}

test "brc43 go-sdk key_deriver happy path" {
    const a = std.testing.allocator;
    const inv = try formatInvoice(a, 0, "testprotocol", "12345");
    defer a.free(inv);
    try std.testing.expectEqualStrings("0-testprotocol-12345", inv);
}

test "brc43 spec examples (single spaces only)" {
    const a = std.testing.allocator;

    const inv1 = try formatInvoice(a, 2, "Private Document Signing", "1337");
    defer a.free(inv1);
    try std.testing.expectEqualStrings("2-private document signing-1337", inv1);

    const inv2 = try formatInvoice(a, 1, "Document Signing", "1");
    defer a.free(inv2);
    try std.testing.expectEqualStrings("1-document signing-1", inv2);

    const inv3 = try formatInvoice(a, 0, "Hello World", "1");
    defer a.free(inv3);
    try std.testing.expectEqualStrings("0-hello world-1", inv3);
}

test "brc43 rejects inputs matching go-sdk key_deriver_test invalid cases" {
    const a = std.testing.allocator;
    var buf: [protocol_name_max_linkage]u8 = undefined;

    try std.testing.expectError(error.ProtocolIdTooShort, normalizeProtocolId("hi", &buf));
    try std.testing.expectError(error.ProtocolIdTooShort, normalizeProtocolId("bad!", &buf));
    try std.testing.expectError(error.InvalidProtocolCharacter, normalizeProtocolId("tests!", &buf));
    try std.testing.expectError(error.InvalidProtocolSuffix, normalizeProtocolId("hello protocol", &buf));
    try std.testing.expectError(error.ProtocolDoubleSpace, normalizeProtocolId("double  space", &buf));
    try std.testing.expectError(error.InvalidSecurityLevel, formatInvoice(a, 3, "tests", "1"));
    try std.testing.expectError(error.InvalidKeyId, formatInvoice(a, 0, "tests", ""));
    const long_key = try a.alloc(u8, 801);
    defer a.free(long_key);
    @memset(long_key, 'x');
    try std.testing.expectError(error.KeyIdTooLong, formatInvoice(a, 2, "tests", long_key));
}

test "brc43 specific linkage revelation allows up to 430 chars" {
    const a = std.testing.allocator;
    // prefix 28 chars + "tests" = 33, well under 430
    const inv = try formatInvoice(a, 0, linkage_prefix ++ "tests", "1");
    defer a.free(inv);
    try std.testing.expect(std.mem.startsWith(u8, inv, "0-specific linkage revelation tests-"));
}

test "brc43 protocol length 401 without linkage fails; 430 with linkage ok" {
    var buf: [protocol_name_max_linkage]u8 = undefined;
    const a = std.testing.allocator;

    const too_long = try a.alloc(u8, 401);
    defer a.free(too_long);
    @memset(too_long, 'a');
    try std.testing.expectError(error.ProtocolNameTooLong, normalizeProtocolId(too_long, &buf));

    const max_link = try a.alloc(u8, 430);
    defer a.free(max_link);
    @memcpy(max_link[0..linkage_prefix.len], linkage_prefix);
    @memset(max_link[linkage_prefix.len..430], 'b');
    const n = try normalizeProtocolId(max_link, &buf);
    try std.testing.expectEqual(@as(usize, 430), n);

    const too_long_link = try a.alloc(u8, 431);
    defer a.free(too_long_link);
    @memcpy(too_long_link[0..28], linkage_prefix);
    @memset(too_long_link[28..431], 'c');
    try std.testing.expectError(error.ProtocolLinkageTooLong, normalizeProtocolId(too_long_link, &buf));
}

test "brc43 formatInvoiceProtocol matches formatInvoice" {
    const a = std.testing.allocator;
    const p: Protocol = .{ .security = 0, .name = "testprotocol" };
    const s1 = try formatInvoice(a, 0, "testprotocol", "12345");
    defer a.free(s1);
    const s2 = try formatInvoiceProtocol(a, p, "12345");
    defer a.free(s2);
    try std.testing.expectEqualStrings(s1, s2);
}
