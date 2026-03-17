const std = @import("std");

pub fn cat(allocator: std.mem.Allocator, left: []const u8, right: []const u8) ![]u8 {
    var out = try allocator.alloc(u8, left.len + right.len);
    @memcpy(out[0..left.len], left);
    @memcpy(out[left.len..], right);
    return out;
}

pub fn substr(allocator: std.mem.Allocator, bytes: []const u8, start: usize, len: usize) ![]u8 {
    if (start >= bytes.len) return allocator.alloc(u8, 0);
    const end = @min(start + len, bytes.len);
    return allocator.dupe(u8, bytes[start..end]);
}
