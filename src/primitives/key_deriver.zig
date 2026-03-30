//! KeyDeriver — BRC-42/43 protocol key derivation.
//! Matches Go `wallet.KeyDeriver` from go-sdk. Uses `ec.PrivateKey.deriveChild` (BRC-42)
//! and `brc43.formatInvoice` to produce protocol-scoped derived keys.
//! https://bsv.brc.dev/key-derivation/0042, https://bsv.brc.dev/key-derivation/0043

const std = @import("std");
const ec = @import("ec.zig");
const brc43 = @import("brc43.zig");
const hex = @import("hex.zig");

/// Counterparty type for key derivation, matching Go `wallet.CounterpartyType`.
pub const CounterpartyType = enum {
    self,
    other,
    anyone,
};

/// Counterparty specification for derivation calls.
pub const Counterparty = struct {
    type_: CounterpartyType = .self,
    /// Required when `type_ == .other`. Compressed SEC1 public key.
    public_key: ?ec.PublicKey = null,
};

/// Protocol specification matching Go `wallet.Protocol`.
pub const Protocol = struct {
    security_level: u8,
    name: []const u8,
};

/// The "anyone" private key: a 32-byte key with value 1 (matches Go `AnyoneKey()`).
fn anyonePrivateKey() ec.PrivateKey {
    var bytes: [32]u8 = .{0} ** 32;
    bytes[31] = 1;
    return ec.PrivateKey.fromBytes(bytes) catch unreachable;
}

/// The "anyone" public key: public key of the anyone private key.
fn anyonePublicKey() ec.PublicKey {
    return anyonePrivateKey().publicKey() catch unreachable;
}

/// KeyDeriver wraps a root private key and provides BRC-42/43 key derivation.
/// Matches Go `wallet.KeyDeriver`.
pub const KeyDeriver = struct {
    root_key: ec.PrivateKey,

    /// Create a new KeyDeriver. If `private_key` is null, uses the "anyone" key.
    pub fn init(private_key: ?ec.PrivateKey) KeyDeriver {
        return .{
            .root_key = private_key orelse anyonePrivateKey(),
        };
    }

    /// Returns the root public key (identity key).
    pub fn identityKey(self: *const KeyDeriver) !ec.PublicKey {
        return self.root_key.publicKey();
    }

    /// Returns identity key as 66-char hex string.
    pub fn identityKeyHex(self: *const KeyDeriver, out: *[66]u8) ![]const u8 {
        const pub_key = try self.identityKey();
        const compressed = pub_key.toCompressedSec1();
        return hex.encodeLower(&compressed, out);
    }

    /// Normalize the counterparty to a concrete PublicKey.
    fn normalizeCounterparty(self: *const KeyDeriver, counterparty: Counterparty) !ec.PublicKey {
        return switch (counterparty.type_) {
            .self => try self.root_key.publicKey(),
            .other => counterparty.public_key orelse return error.InvalidEncoding,
            .anyone => anyonePublicKey(),
        };
    }

    /// Derive a public key using BRC-42/43. Matches Go `KeyDeriver.DerivePublicKey`.
    ///
    /// When `for_self` is true, derives private key first then extracts public key
    /// (used when you own the root key and need the derived public key for yourself).
    /// When `for_self` is false, derives the counterparty's child public key
    /// (used to derive what the counterparty's derived pubkey would be).
    pub fn derivePublicKey(
        self: *const KeyDeriver,
        allocator: std.mem.Allocator,
        protocol: Protocol,
        key_id: []const u8,
        counterparty: Counterparty,
        for_self: bool,
    ) !ec.PublicKey {
        const counterparty_key = try self.normalizeCounterparty(counterparty);
        const invoice = try brc43.formatInvoice(allocator, protocol.security_level, protocol.name, key_id);
        defer allocator.free(invoice);

        if (for_self) {
            const derived_priv = try self.root_key.deriveChild(counterparty_key, invoice);
            return derived_priv.publicKey();
        }

        return counterparty_key.deriveChild(self.root_key, invoice);
    }

    /// Derive a private key using BRC-42/43. Matches Go `KeyDeriver.DerivePrivateKey`.
    pub fn derivePrivateKey(
        self: *const KeyDeriver,
        allocator: std.mem.Allocator,
        protocol: Protocol,
        key_id: []const u8,
        counterparty: Counterparty,
    ) !ec.PrivateKey {
        const counterparty_key = try self.normalizeCounterparty(counterparty);
        const invoice = try brc43.formatInvoice(allocator, protocol.security_level, protocol.name, key_id);
        defer allocator.free(invoice);

        return self.root_key.deriveChild(counterparty_key, invoice);
    }

    /// Reveal the specific key association (HMAC of shared secret + invoice).
    /// Matches Go `KeyDeriver.RevealSpecificSecret`.
    pub fn revealSpecificSecret(
        self: *const KeyDeriver,
        allocator: std.mem.Allocator,
        counterparty: Counterparty,
        protocol: Protocol,
        key_id: []const u8,
    ) ![32]u8 {
        const counterparty_key = try self.normalizeCounterparty(counterparty);
        const shared = try self.root_key.deriveSharedSecret(counterparty_key);
        const comp = shared.toCompressedSec1();

        const invoice = try brc43.formatInvoice(allocator, protocol.security_level, protocol.name, key_id);
        defer allocator.free(invoice);

        const crypto_hash = @import("../crypto/hash.zig");
        return crypto_hash.hmacSha256(invoice, &comp);
    }
};

// ── Tests ──────────────────────────────────────────────────────────────

test "KeyDeriver identity key matches root public key" {
    const root_bytes: [32]u8 = .{0} ** 31 ++ .{42};
    const root_key = try ec.PrivateKey.fromBytes(root_bytes);
    const kd = KeyDeriver.init(root_key);

    const identity = try kd.identityKey();
    const root_pub = try root_key.publicKey();
    try std.testing.expect(identity.eql(root_pub));
}

test "KeyDeriver identity key hex" {
    const root_bytes: [32]u8 = .{0} ** 31 ++ .{42};
    const root_key = try ec.PrivateKey.fromBytes(root_bytes);
    const kd = KeyDeriver.init(root_key);

    var buf: [66]u8 = undefined;
    const hex_str = try kd.identityKeyHex(&buf);
    try std.testing.expectEqual(@as(usize, 66), hex_str.len);
    try std.testing.expect(hex_str[0] == '0' and (hex_str[1] == '2' or hex_str[1] == '3'));
}

test "KeyDeriver nil uses anyone key" {
    const kd = KeyDeriver.init(null);
    const anyone_pub = anyonePublicKey();
    const identity = try kd.identityKey();
    try std.testing.expect(identity.eql(anyone_pub));
}

test "KeyDeriver normalizeCounterparty self" {
    const root_bytes: [32]u8 = .{0} ** 31 ++ .{42};
    const root_key = try ec.PrivateKey.fromBytes(root_bytes);
    const kd = KeyDeriver.init(root_key);

    const root_pub = try root_key.publicKey();
    const normalized = try kd.normalizeCounterparty(.{ .type_ = .self });
    try std.testing.expect(normalized.eql(root_pub));
}

test "KeyDeriver normalizeCounterparty anyone" {
    const root_bytes: [32]u8 = .{0} ** 31 ++ .{42};
    const root_key = try ec.PrivateKey.fromBytes(root_bytes);
    const kd = KeyDeriver.init(root_key);

    const anyone_pub = anyonePublicKey();
    const normalized = try kd.normalizeCounterparty(.{ .type_ = .anyone });
    try std.testing.expect(normalized.eql(anyone_pub));
}

test "KeyDeriver normalizeCounterparty other" {
    const root_bytes: [32]u8 = .{0} ** 31 ++ .{42};
    const root_key = try ec.PrivateKey.fromBytes(root_bytes);
    const kd = KeyDeriver.init(root_key);

    const cp_bytes: [32]u8 = .{0} ** 31 ++ .{69};
    const cp_key = try ec.PrivateKey.fromBytes(cp_bytes);
    const cp_pub = try cp_key.publicKey();

    const normalized = try kd.normalizeCounterparty(.{ .type_ = .other, .public_key = cp_pub });
    try std.testing.expect(normalized.eql(cp_pub));
}

test "KeyDeriver normalizeCounterparty other without key fails" {
    const root_bytes: [32]u8 = .{0} ** 31 ++ .{42};
    const root_key = try ec.PrivateKey.fromBytes(root_bytes);
    const kd = KeyDeriver.init(root_key);

    try std.testing.expectError(error.InvalidEncoding, kd.normalizeCounterparty(.{ .type_ = .other }));
}

test "KeyDeriver derivePublicKey for self" {
    const a = std.testing.allocator;
    const root_bytes: [32]u8 = .{0} ** 31 ++ .{42};
    const root_key = try ec.PrivateKey.fromBytes(root_bytes);
    const kd = KeyDeriver.init(root_key);

    const cp_bytes: [32]u8 = .{0} ** 31 ++ .{69};
    const cp_key = try ec.PrivateKey.fromBytes(cp_bytes);
    const cp_pub = try cp_key.publicKey();

    const protocol = Protocol{ .security_level = 0, .name = "testprotocol" };
    const derived = try kd.derivePublicKey(a, protocol, "12345", .{ .type_ = .other, .public_key = cp_pub }, true);

    // Verify this is a valid compressed public key
    const comp = derived.toCompressedSec1();
    try std.testing.expect(comp[0] == 0x02 or comp[0] == 0x03);
}

test "KeyDeriver derivePublicKey for counterparty" {
    const a = std.testing.allocator;
    const root_bytes: [32]u8 = .{0} ** 31 ++ .{42};
    const root_key = try ec.PrivateKey.fromBytes(root_bytes);
    const kd = KeyDeriver.init(root_key);

    const cp_bytes: [32]u8 = .{0} ** 31 ++ .{69};
    const cp_key = try ec.PrivateKey.fromBytes(cp_bytes);
    const cp_pub = try cp_key.publicKey();

    const protocol = Protocol{ .security_level = 0, .name = "testprotocol" };
    const derived = try kd.derivePublicKey(a, protocol, "12345", .{ .type_ = .other, .public_key = cp_pub }, false);

    const comp = derived.toCompressedSec1();
    try std.testing.expect(comp[0] == 0x02 or comp[0] == 0x03);
}

test "KeyDeriver derivePrivateKey" {
    const a = std.testing.allocator;
    const root_bytes: [32]u8 = .{0} ** 31 ++ .{42};
    const root_key = try ec.PrivateKey.fromBytes(root_bytes);
    const kd = KeyDeriver.init(root_key);

    const cp_bytes: [32]u8 = .{0} ** 31 ++ .{69};
    const cp_key = try ec.PrivateKey.fromBytes(cp_bytes);
    const cp_pub = try cp_key.publicKey();

    const protocol = Protocol{ .security_level = 0, .name = "testprotocol" };
    const derived = try kd.derivePrivateKey(a, protocol, "12345", .{ .type_ = .other, .public_key = cp_pub });

    // Derived private key should produce a valid public key
    const derived_pub = try derived.publicKey();
    const comp = derived_pub.toCompressedSec1();
    try std.testing.expect(comp[0] == 0x02 or comp[0] == 0x03);
}

test "KeyDeriver forSelf derived pubkey matches private derivation" {
    const a = std.testing.allocator;
    const root_bytes: [32]u8 = .{0} ** 31 ++ .{42};
    const root_key = try ec.PrivateKey.fromBytes(root_bytes);
    const kd = KeyDeriver.init(root_key);

    const cp_bytes: [32]u8 = .{0} ** 31 ++ .{69};
    const cp_key = try ec.PrivateKey.fromBytes(cp_bytes);
    const cp_pub = try cp_key.publicKey();

    const protocol = Protocol{ .security_level = 0, .name = "testprotocol" };
    const counterparty = Counterparty{ .type_ = .other, .public_key = cp_pub };

    // forSelf: derive private then get pubkey
    const for_self_pub = try kd.derivePublicKey(a, protocol, "12345", counterparty, true);

    // Also derive private key directly and check pubkeys match
    const derived_priv = try kd.derivePrivateKey(a, protocol, "12345", counterparty);
    const priv_pub = try derived_priv.publicKey();

    try std.testing.expect(for_self_pub.eql(priv_pub));
}

test "KeyDeriver anyone derivation works" {
    const a = std.testing.allocator;
    const kd = KeyDeriver.init(null);

    const cp_bytes: [32]u8 = .{0} ** 31 ++ .{69};
    const cp_key = try ec.PrivateKey.fromBytes(cp_bytes);
    const cp_pub = try cp_key.publicKey();

    const protocol = Protocol{ .security_level = 0, .name = "testprotocol" };
    const derived = try kd.derivePublicKey(a, protocol, "12345", .{ .type_ = .other, .public_key = cp_pub }, false);

    const comp = derived.toCompressedSec1();
    try std.testing.expect(comp[0] == 0x02 or comp[0] == 0x03);
}

test "KeyDeriver revealSpecificSecret" {
    const a = std.testing.allocator;
    const root_bytes: [32]u8 = .{0} ** 31 ++ .{42};
    const root_key = try ec.PrivateKey.fromBytes(root_bytes);
    const kd = KeyDeriver.init(root_key);

    const cp_bytes: [32]u8 = .{0} ** 31 ++ .{69};
    const cp_key = try ec.PrivateKey.fromBytes(cp_bytes);
    const cp_pub = try cp_key.publicKey();

    const protocol = Protocol{ .security_level = 0, .name = "testprotocol" };
    const secret = try kd.revealSpecificSecret(a, .{ .type_ = .other, .public_key = cp_pub }, protocol, "12345");

    // Should be 32 bytes (HMAC-SHA256 output)
    try std.testing.expectEqual(@as(usize, 32), secret.len);

    // Verify manually: HMAC(invoice, sharedSecret.compressed)
    const shared = try root_key.deriveSharedSecret(cp_pub);
    const comp = shared.toCompressedSec1();
    const crypto_hash = @import("../crypto/hash.zig");
    const invoice = try brc43.formatInvoice(a, 0, "testprotocol", "12345");
    defer a.free(invoice);
    const expected = crypto_hash.hmacSha256(invoice, &comp);
    try std.testing.expectEqualSlices(u8, &expected, &secret);
}
