const std = @import("std");
const transaction = @import("../transaction/lib.zig");
const types = @import("types.zig");
const http_post = @import("http_post.zig");
const helpers = @import("helpers.zig");

pub const TAALBroadcast = struct {
    api_key: []const u8 = "",

    pub fn broadcast(
        self: TAALBroadcast,
        allocator: std.mem.Allocator,
        tx: *const transaction.Transaction,
    ) !types.BroadcastResult {
        const serialized = try tx.serialize(allocator);
        defer allocator.free(serialized);

        var hdrs: std.ArrayList(std.http.Header) = .empty;
        defer hdrs.deinit(allocator);
        try hdrs.append(allocator, .{ .name = "Content-Type", .value = "application/octet-stream" });
        if (self.api_key.len > 0) {
            try hdrs.append(allocator, .{ .name = "Authorization", .value = self.api_key });
        }

        const post = try http_post.postBodyAlloc(
            allocator,
            "https://api.taal.com/api/v1/broadcast",
            hdrs.items,
            serialized,
        );
        defer allocator.free(post.body);

        const parsed = std.json.parseFromSlice(std.json.Value, allocator, post.body, .{}) catch {
            const code = try std.fmt.allocPrint(allocator, "{d}", .{@intFromEnum(post.status)});
            const desc = try allocator.dupe(u8, "unknown error");
            return .{ .err = .{ .code = code, .description = desc } };
        };
        defer parsed.deinit();

        const obj = switch (parsed.value) {
            .object => |o| o,
            else => {
                const code = try std.fmt.allocPrint(allocator, "{d}", .{@intFromEnum(post.status)});
                const desc = try allocator.dupe(u8, "unknown error");
                return .{ .err = .{ .code = code, .description = desc } };
            },
        };

        const err_str: []const u8 = blk: {
            const ev = obj.get("error") orelse break :blk "";
            break :blk switch (ev) {
                .string => |s| s,
                else => "",
            };
        };

        const status_ok = @intFromEnum(post.status) == 200;
        const dup_ok = std.mem.indexOf(u8, err_str, "txn-already-known") != null;
        if (!status_ok and !dup_ok) {
            const code = try std.fmt.allocPrint(allocator, "{d}", .{@intFromEnum(post.status)});
            const desc = try allocator.dupe(u8, err_str);
            return .{ .err = .{ .code = code, .description = desc } };
        }

        const h = try tx.txid(allocator);
        const txid_str = try helpers.txidDisplayHex(allocator, h);
        return .{ .ok = .{ .txid = txid_str } };
    }
};

test "taal json decode path" {
    const allocator = std.testing.allocator;
    const sample =
        \\{"txid":"abc","status":200,"error":""}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, sample, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    const err_v = obj.get("error").?;
    const es = switch (err_v) {
        .string => |s| s,
        else => "",
    };
    try std.testing.expectEqualStrings("", es);
}
