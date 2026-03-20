const std = @import("std");
const transaction = @import("../transaction/lib.zig");
const types = @import("types.zig");
const http_post = @import("http_post.zig");
const helpers = @import("helpers.zig");

pub const ArcStatus = []const u8;

pub const rejected: ArcStatus = "REJECTED";

pub const Arc = struct {
    api_url: []const u8,
    api_key: []const u8 = "",
    callback_url: ?[]const u8 = null,
    callback_token: ?[]const u8 = null,
    callback_batch: bool = false,
    full_status_updates: bool = false,
    max_timeout: ?i32 = null,
    skip_fee_validation: bool = false,
    skip_script_validation: bool = false,
    skip_tx_validation: bool = false,
    cumulative_fee_validation: bool = false,
    wait_for_status: []const u8 = "",
    wait_for: []const u8 = "",
    verbose: bool = false,

    fn joinUrl(allocator: std.mem.Allocator, base: []const u8, suffix: []const u8) ![]u8 {
        var b = base;
        while (b.len > 0 and b[b.len - 1] == '/') b = b[0 .. b.len - 1];
        return std.fmt.allocPrint(allocator, "{s}/{s}", .{ b, suffix });
    }

    fn arcPayload(self: *const Arc, allocator: std.mem.Allocator, tx: *const transaction.Transaction) ![]u8 {
        _ = self;
        for (tx.inputs) |inp| {
            if (inp.source_output == null) {
                return tx.serialize(allocator);
            }
        }
        return tx.serializeExtended(allocator);
    }

    /// POST /tx — returns parsed JSON tree (caller `deinit`s).
    pub fn arcBroadcast(
        self: *const Arc,
        allocator: std.mem.Allocator,
        tx: *const transaction.Transaction,
    ) !std.json.Parsed(std.json.Value) {
        const payload = try self.arcPayload(allocator, tx);
        defer allocator.free(payload);

        const url = try joinUrl(allocator, self.api_url, "tx");
        defer allocator.free(url);

        var hdrs: std.ArrayList(std.http.Header) = .empty;
        defer hdrs.deinit(allocator);
        try hdrs.append(allocator, .{ .name = "Content-Type", .value = "application/octet-stream" });

        var auth_bearer: ?[]u8 = null;
        defer if (auth_bearer) |b| allocator.free(b);
        if (self.api_key.len > 0) {
            auth_bearer = try std.fmt.allocPrint(allocator, "Bearer {s}", .{self.api_key});
            try hdrs.append(allocator, .{ .name = "Authorization", .value = auth_bearer.? });
        }
        if (self.callback_url) |u| {
            try hdrs.append(allocator, .{ .name = "X-CallbackUrl", .value = u });
        }
        if (self.callback_token) |t| {
            try hdrs.append(allocator, .{ .name = "X-CallbackToken", .value = t });
        }
        if (self.callback_batch) {
            try hdrs.append(allocator, .{ .name = "X-CallbackBatch", .value = "true" });
        }
        if (self.full_status_updates) {
            try hdrs.append(allocator, .{ .name = "X-FullStatusUpdates", .value = "true" });
        }
        var max_timeout_s: ?[]u8 = null;
        defer if (max_timeout_s) |x| allocator.free(x);
        if (self.max_timeout) |m| {
            max_timeout_s = try std.fmt.allocPrint(allocator, "{d}", .{m});
            try hdrs.append(allocator, .{ .name = "X-MaxTimeout", .value = max_timeout_s.? });
        }
        if (self.skip_fee_validation) {
            try hdrs.append(allocator, .{ .name = "X-SkipFeeValidation", .value = "true" });
        }
        if (self.skip_script_validation) {
            try hdrs.append(allocator, .{ .name = "X-SkipScriptValidation", .value = "true" });
        }
        if (self.skip_tx_validation) {
            try hdrs.append(allocator, .{ .name = "X-SkipTxValidation", .value = "true" });
        }
        if (self.cumulative_fee_validation) {
            try hdrs.append(allocator, .{ .name = "X-CumulativeFeeValidation", .value = "true" });
        }
        if (self.wait_for_status.len > 0) {
            try hdrs.append(allocator, .{ .name = "X-WaitForStatus", .value = self.wait_for_status });
        }
        if (self.wait_for.len > 0) {
            try hdrs.append(allocator, .{ .name = "X-WaitFor", .value = self.wait_for });
        }

        const post = try http_post.postBodyAlloc(allocator, url, hdrs.items, payload);
        defer allocator.free(post.body);

        if (self.verbose) {
            std.debug.print("arc broadcast msg {s}\n", .{post.body});
        }

        return std.json.parseFromSlice(std.json.Value, allocator, post.body, .{});
    }

    pub fn broadcast(
        self: *const Arc,
        allocator: std.mem.Allocator,
        tx: *const transaction.Transaction,
    ) !types.BroadcastResult {
        const parsed = self.arcBroadcast(allocator, tx) catch |err| {
            const code = try allocator.dupe(u8, "500");
            const desc = try std.fmt.allocPrint(allocator, "{s}", .{@errorName(err)});
            return .{ .err = .{ .code = code, .description = desc } };
        };
        defer parsed.deinit();

        const obj = switch (parsed.value) {
            .object => |o| o,
            else => {
                const code = try allocator.dupe(u8, "500");
                const desc = try allocator.dupe(u8, "invalid json");
                return .{ .err = .{ .code = code, .description = desc } };
            },
        };

        const tx_status_opt = obj.get("txStatus");
        if (tx_status_opt) |ts| {
            const ts_str: []const u8 = switch (ts) {
                .string => |s| s,
                else => "",
            };
            if (std.mem.eql(u8, ts_str, rejected)) {
                const extra = obj.get("extraInfo") orelse std.json.Value{ .string = "" };
                const extra_info: []const u8 = switch (extra) {
                    .string => |s| s,
                    else => "",
                };
                const code = try allocator.dupe(u8, "400");
                const desc = try allocator.dupe(u8, extra_info);
                return .{ .err = .{ .code = code, .description = desc } };
            }
        }

        const status_val = obj.get("status") orelse {
            const code = try allocator.dupe(u8, "500");
            const desc = try allocator.dupe(u8, "missing status");
            return .{ .err = .{ .code = code, .description = desc } };
        };
        const status_int: i32 = switch (status_val) {
            .integer => |i| @intCast(i),
            .float => |f| @intFromFloat(f),
            else => -1,
        };

        if (status_int == 200) {
            const title_v = obj.get("title") orelse std.json.Value{ .string = "" };
            const title: []const u8 = switch (title_v) {
                .string => |s| s,
                else => "",
            };
            const txid_v = obj.get("txid") orelse std.json.Value{ .string = "" };
            const txid_s: []const u8 = switch (txid_v) {
                .string => |s| s,
                else => "",
            };
            if (txid_s.len == 0) {
                const code = try allocator.dupe(u8, "500");
                const desc = try allocator.dupe(u8, "empty txid in arc response");
                return .{ .err = .{ .code = code, .description = desc } };
            }
            const txid_owned = try allocator.dupe(u8, txid_s);
            errdefer allocator.free(txid_owned);
            var msg_owned: []u8 = &[_]u8{};
            if (title.len > 0) {
                msg_owned = try allocator.dupe(u8, title);
            }
            return .{ .ok = .{ .txid = txid_owned, .message = msg_owned } };
        }

        const title_v = obj.get("title") orelse std.json.Value{ .string = "" };
        const title: []const u8 = switch (title_v) {
            .string => |s| s,
            else => "",
        };
        const code = try std.fmt.allocPrint(allocator, "{d}", .{status_int});
        const desc = try allocator.dupe(u8, title);
        return .{ .err = .{ .code = code, .description = desc } };
    }

    /// GET `{api_url}/tx/{txid}` — returns parsed JSON (caller `deinit`s).
    pub fn status(
        self: *const Arc,
        allocator: std.mem.Allocator,
        txid_hex: []const u8,
    ) !std.json.Parsed(std.json.Value) {
        const url = try joinUrl(allocator, self.api_url, "tx");
        defer allocator.free(url);
        const full = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ url, txid_hex });
        defer allocator.free(full);

        var hdrs: std.ArrayList(std.http.Header) = .empty;
        defer hdrs.deinit(allocator);
        var auth_bearer: ?[]u8 = null;
        defer if (auth_bearer) |b| allocator.free(b);
        if (self.api_key.len > 0) {
            auth_bearer = try std.fmt.allocPrint(allocator, "Bearer {s}", .{self.api_key});
            try hdrs.append(allocator, .{ .name = "Authorization", .value = auth_bearer.? });
        }

        const get = try http_post.getBodyAlloc(allocator, full, hdrs.items);
        defer allocator.free(get.body);

        return std.json.parseFromSlice(std.json.Value, allocator, get.body, .{});
    }
};

test "arc extended payload when all inputs have source" {
    const allocator = std.testing.allocator;
    const out = transaction.Output{ .satoshis = 1, .locking_script = .{ .bytes = &[_]u8{0x51} } };
    const tx = transaction.Transaction{
        .version = 1,
        .inputs = &.{.{
            .previous_outpoint = .{
                .txid = .{ .bytes = [_]u8{1} ** 32 },
                .index = 0,
            },
            .unlocking_script = .{ .bytes = &[_]u8{} },
            .sequence = 0xffffffff,
            .source_output = out,
        }},
        .outputs = &.{},
        .lock_time = 0,
    };
    const ext = try tx.serializeExtended(allocator);
    defer allocator.free(ext);
    try std.testing.expect(ext.len > 0);
}
