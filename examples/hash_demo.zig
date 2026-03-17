const std = @import("std");
const bsvz = @import("bsvz");

pub fn main() !void {
    const digest = bsvz.crypto.hash.sha256("bsvz");
    std.debug.print("{s}\n", .{std.fmt.fmtSliceHexLower(&digest.bytes)});
}
