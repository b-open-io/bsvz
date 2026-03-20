const std = @import("std");
const hash = @import("../crypto/hash.zig");

pub const Error = error{
    NotEnoughEntropy,
    ReseedRequired,
    RequestTooLarge,
} || std.mem.Allocator.Error;

pub const DRBG = struct {
    allocator: std.mem.Allocator,
    k: [32]u8,
    v: [32]u8,
    reseed_counter: usize,

    pub fn init(entropy: []const u8, nonce: []const u8, allocator: std.mem.Allocator) Error!DRBG {
        if (entropy.len < 32) return error.NotEnoughEntropy;
        var drbg = DRBG{
            .allocator = allocator,
            .k = [_]u8{0} ** 32,
            .v = [_]u8{0x01} ** 32,
            .reseed_counter = 1,
        };
        var seed_buf = try std.ArrayList(u8).initCapacity(allocator, entropy.len + nonce.len);
        defer seed_buf.deinit(allocator);
        try seed_buf.appendSlice(allocator, entropy);
        try seed_buf.appendSlice(allocator, nonce);
        try drbg.update(seed_buf.items);
        return drbg;
    }

    pub fn generate(self: *DRBG, allocator: std.mem.Allocator, length: usize) Error![]u8 {
        if (self.reseed_counter > 10000) return error.ReseedRequired;
        if (length > 937) return error.RequestTooLarge;

        const out = try allocator.alloc(u8, length);
        errdefer allocator.free(out);
        var filled: usize = 0;
        while (filled < length) {
            self.v = hash.hmacSha256(self.v[0..], self.k[0..]);
            const take = @min(self.v.len, length - filled);
            @memcpy(out[filled .. filled + take], self.v[0..take]);
            filled += take;
        }

        try self.update(null);
        self.reseed_counter += 1;
        return out;
    }

    pub fn reseed(self: *DRBG, entropy: []const u8) Error!void {
        if (entropy.len < 32) return error.NotEnoughEntropy;
        try self.update(entropy);
        self.reseed_counter = 1;
    }

    fn update(self: *DRBG, seed: ?[]const u8) Error!void {
        const a = self.allocator;
        const seed_len = if (seed) |s| s.len else 0;
        var buf = try std.ArrayList(u8).initCapacity(a, self.v.len + 1 + seed_len);
        defer buf.deinit(a);
        try buf.appendSlice(a, self.v[0..]);
        try buf.append(a, 0x00);
        if (seed) |s| try buf.appendSlice(a, s);
        self.k = hash.hmacSha256(buf.items, self.k[0..]);

        self.v = hash.hmacSha256(self.v[0..], self.k[0..]);
        if (seed) |s| {
            buf.clearRetainingCapacity();
            try buf.appendSlice(a, self.v[0..]);
            try buf.append(a, 0x01);
            try buf.appendSlice(a, s);
            self.k = hash.hmacSha256(buf.items, self.k[0..]);
            self.v = hash.hmacSha256(self.v[0..], self.k[0..]);
        }
    }
};

test "drbg generate length" {
    var entropy = [_]u8{0x01} ** 32;
    var nonce = [_]u8{0x02} ** 16;
    var d = try DRBG.init(&entropy, &nonce, std.testing.allocator);
    const out = try d.generate(std.testing.allocator, 64);
    defer std.testing.allocator.free(out);
    try std.testing.expectEqual(@as(usize, 64), out.len);
}
