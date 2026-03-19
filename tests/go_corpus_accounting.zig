const std = @import("std");

const corpus_path = "../go-sdk/script/interpreter/data/script_tests.json";

fn accessOrSkip(rel_path: []const u8) !void {
    std.fs.cwd().access(rel_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return error.SkipZigTest,
        else => return err,
    };
}

fn collectAccountedRowRefs(allocator: std.mem.Allocator) !std.AutoHashMap(usize, void) {
    var rows = std.AutoHashMap(usize, void).init(allocator);
    errdefer rows.deinit();

    var dir = try std.fs.cwd().openDir("tests", .{ .iterate = true });
    defer dir.close();

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.startsWith(u8, entry.name, "go_")) continue;
        if (!std.mem.endsWith(u8, entry.name, "_vectors.zig")) continue;

        const source = try dir.readFileAlloc(allocator, entry.name, 512 * 1024);
        defer allocator.free(source);

        var cursor: usize = 0;
        while (std.mem.indexOfPos(u8, source, cursor, ".row")) |row_pos| {
            const eq_pos = std.mem.indexOfPos(u8, source, row_pos, "=") orelse break;
            var digits_start = eq_pos + 1;
            while (digits_start < source.len and std.ascii.isWhitespace(source[digits_start])) : (digits_start += 1) {}

            var digits_end = digits_start;
            while (digits_end < source.len and std.ascii.isDigit(source[digits_end])) : (digits_end += 1) {}
            if (digits_end > digits_start) {
                const row = try std.fmt.parseInt(usize, source[digits_start..digits_end], 10);
                try rows.put(row, {});
            }
            cursor = digits_end;
        }
    }

    return rows;
}

test "all go corpus rows are explicitly accounted for" {
    const allocator = std.testing.allocator;
    try accessOrSkip(corpus_path);

    var accounted_rows = try collectAccountedRowRefs(allocator);
    defer accounted_rows.deinit();

    const file = try std.fs.cwd().readFileAlloc(allocator, corpus_path, 8 * 1024 * 1024);
    defer allocator.free(file);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, file, .{});
    defer parsed.deinit();

    if (parsed.value != .array) return error.InvalidEncoding;

    var uncovered_count: usize = 0;
    var first_missing_row: ?usize = null;

    for (parsed.value.array.items, 0..) |value, index| {
        if (accounted_rows.contains(index)) continue;
        _ = value;
        uncovered_count += 1;
        if (first_missing_row == null) first_missing_row = index;
    }

    try std.testing.expectEqual(@as(usize, 0), uncovered_count);
    try std.testing.expectEqual(@as(?usize, null), first_missing_row);
}
