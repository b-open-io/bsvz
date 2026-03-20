const std = @import("std");
const transaction = @import("../transaction/lib.zig");
const types = @import("types.zig");
const http_post = @import("http_post.zig");
const helpers = @import("helpers.zig");

pub const Network = enum {
    main,
    testnet,

    fn pathSegment(self: Network) []const u8 {
        return switch (self) {
            .main => "main",
            .testnet => "test",
        };
    }
};

pub const WhatsOnChain = struct {
    network: Network = .main,
    api_key: []const u8 = "",

    pub fn broadcast(
        self: WhatsOnChain,
        allocator: std.mem.Allocator,
        tx: *const transaction.Transaction,
    ) !types.BroadcastResult {
        const serialized = try tx.serialize(allocator);
        defer allocator.free(serialized);

        const txhex = try helpers.hexEncodeLower(allocator, serialized);
        defer allocator.free(txhex);

        const body = try std.fmt.allocPrint(allocator, "{{\"txhex\":\"{s}\"}}", .{txhex});
        defer allocator.free(body);

        const url = try std.fmt.allocPrint(
            allocator,
            "https://api.whatsonchain.com/v1/bsv/{s}/tx/raw",
            .{self.network.pathSegment()},
        );
        defer allocator.free(url);

        var hdrs: std.ArrayList(std.http.Header) = .empty;
        defer hdrs.deinit(allocator);
        try hdrs.append(allocator, .{ .name = "Content-Type", .value = "application/json" });
        var auth_bearer: ?[]u8 = null;
        defer if (auth_bearer) |b| allocator.free(b);
        if (self.api_key.len > 0) {
            auth_bearer = try std.fmt.allocPrint(allocator, "Bearer {s}", .{self.api_key});
            try hdrs.append(allocator, .{ .name = "Authorization", .value = auth_bearer.? });
        }

        const post = try http_post.postBodyAlloc(allocator, url, hdrs.items, body);
        defer allocator.free(post.body);

        if (post.status != .ok) {
            const code = try std.fmt.allocPrint(allocator, "{d}", .{@intFromEnum(post.status)});
            const desc = try allocator.dupe(u8, post.body);
            return .{ .err = .{ .code = code, .description = desc } };
        }

        const h = try tx.txid(allocator);
        const txid_str = try helpers.txidDisplayHex(allocator, h);
        return .{ .ok = .{ .txid = txid_str } };
    }
};

test "woc json body shape" {
    const allocator = std.testing.allocator;
    const ser = &[_]u8{ 0x01, 0xab };
    const txhex = try helpers.hexEncodeLower(allocator, ser);
    defer allocator.free(txhex);
    const body = try std.fmt.allocPrint(allocator, "{{\"txhex\":\"{s}\"}}", .{txhex});
    defer allocator.free(body);
    try std.testing.expect(std.mem.eql(u8, body, "{\"txhex\":\"01ab\"}"));
}
