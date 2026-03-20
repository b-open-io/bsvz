const std = @import("std");
const bsvz = @import("bsvz");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    // Replace this with a real signed transaction hex string before running.
    const tx_hex =
        "010000000100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff010100000000000000015100000000";

    var tx = bsvz.transaction.Transaction.parseHex(allocator, tx_hex) catch |err| {
        std.debug.print("failed to parse tx hex: {s}\n", .{@errorName(err)});
        return err;
    };
    defer tx.deinit(allocator);

    const broadcaster = bsvz.broadcast.arc.Arc{
        .api_url = "https://arc.gorillapool.io",
    };

    var result = try broadcaster.broadcast(allocator, &tx);
    defer result.deinit(allocator);

    switch (result) {
        .ok => |success| {
            if (success.message.len > 0) {
                std.debug.print("broadcast ok: {s} ({s})\n", .{ success.txid, success.message });
            } else {
                std.debug.print("broadcast ok: {s}\n", .{success.txid});
            }
        },
        .err => |failure| {
            std.debug.print("broadcast failed [{s}]: {s}\n", .{ failure.code, failure.description });
        },
    }
}
