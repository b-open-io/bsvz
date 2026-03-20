const std = @import("std");

pub const PostResult = struct {
    status: std.http.Status,
    body: []u8,
};

fn readResponseBody(allocator: std.mem.Allocator, resp: *std.http.Client.Response, buf: []u8) ![]u8 {
    var body_reader = resp.reader(buf);
    return body_reader.allocRemaining(allocator, std.io.Limit.limited(4 * 1024 * 1024));
}

/// POST with body; returns allocated response body.
pub fn postBodyAlloc(
    allocator: std.mem.Allocator,
    url: []const u8,
    extra_headers: []const std.http.Header,
    payload: []const u8,
) !PostResult {
    var client: std.http.Client = .{ .allocator = allocator };
    defer client.deinit();

    const uri = try std.Uri.parse(url);
    var req = try client.request(.POST, uri, .{
        .extra_headers = extra_headers,
    });
    defer req.deinit();

    try req.sendBodyComplete(@constCast(payload));

    var redirect_buf: [8192]u8 = undefined;
    var resp = try req.receiveHead(&redirect_buf);

    var transfer_buf: [8192]u8 = undefined;
    const body = try readResponseBody(allocator, &resp, &transfer_buf);

    return .{
        .status = resp.head.status,
        .body = body,
    };
}

/// GET; returns allocated response body.
pub fn getBodyAlloc(
    allocator: std.mem.Allocator,
    url: []const u8,
    extra_headers: []const std.http.Header,
) !PostResult {
    var client: std.http.Client = .{ .allocator = allocator };
    defer client.deinit();

    const uri = try std.Uri.parse(url);
    var req = try client.request(.GET, uri, .{
        .extra_headers = extra_headers,
    });
    defer req.deinit();

    try req.sendBodiless();

    var redirect_buf: [8192]u8 = undefined;
    var resp = try req.receiveHead(&redirect_buf);

    var transfer_buf: [8192]u8 = undefined;
    const body = try readResponseBody(allocator, &resp, &transfer_buf);

    return .{
        .status = resp.head.status,
        .body = body,
    };
}
