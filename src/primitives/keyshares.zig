const std = @import("std");
const base58 = @import("base58.zig");

pub const Error = error{
    InvalidShareFormat,
    InvalidThreshold,
    IntegrityMismatch,
    DuplicateShare,
    InvalidPoint,
};

pub const Curve = struct {
    pub const p: u256 = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f;
};

pub const Point = struct {
    x: u256,
    y: u256,

    pub fn new(x: u256, y: u256) Point {
        return .{
            .x = modReduce(x),
            .y = modReduce(y),
        };
    }

    pub fn toString(self: Point, allocator: std.mem.Allocator) ![]u8 {
        const x_full = u256ToBytes(self.x);
        const y_full = u256ToBytes(self.y);
        const x_str = try base58.encode(allocator, trimLeadingZeros(&x_full));
        defer allocator.free(x_str);
        const y_str = try base58.encode(allocator, trimLeadingZeros(&y_full));
        defer allocator.free(y_str);
        return std.fmt.allocPrint(allocator, "{s}.{s}", .{ x_str, y_str });
    }

    pub fn fromString(allocator: std.mem.Allocator, text: []const u8) !Point {
        var it = std.mem.splitScalar(u8, text, '.');
        const x_part = it.next() orelse return error.InvalidShareFormat;
        const y_part = it.next() orelse return error.InvalidShareFormat;
        if (it.next() != null) return error.InvalidShareFormat;
        const x_bytes = try base58.decode(allocator, x_part);
        defer allocator.free(x_bytes);
        const y_bytes = try base58.decode(allocator, y_part);
        defer allocator.free(y_bytes);
        return Point.new(bytesToU256(x_bytes), bytesToU256(y_bytes));
    }
};

pub const Polynomial = struct {
    points: []const Point,
    threshold: usize,

    pub fn valueAt(self: Polynomial, x: u256) u256 {
        if (self.threshold == 0) return 0;
        var y: u256 = 0;
        var i: usize = 0;
        while (i < self.threshold) : (i += 1) {
            var term = self.points[i].y;
            var j: usize = 0;
            while (j < self.threshold) : (j += 1) {
                if (i == j) continue;
                const numerator = modSub(x, self.points[j].x);
                const denominator = modSub(self.points[i].x, self.points[j].x);
                const denom_inv = modInv(denominator);
                term = modMul(term, modMul(numerator, denom_inv));
            }
            y = modAdd(y, term);
        }
        return y;
    }
};

pub const KeyShares = struct {
    points: []Point,
    threshold: usize,
    integrity: [8]u8,

    pub fn toBackupFormat(self: KeyShares, allocator: std.mem.Allocator) ![][]u8 {
        var out = try allocator.alloc([]u8, self.points.len);
        var i: usize = 0;
        while (i < self.points.len) : (i += 1) {
            const point_str = try self.points[i].toString(allocator);
            defer allocator.free(point_str);
            out[i] = try std.fmt.allocPrint(
                allocator,
                "{s}.{d}.{s}",
                .{ point_str, self.threshold, self.integrity[0..] },
            );
        }
        return out;
    }

    pub fn fromBackupFormat(allocator: std.mem.Allocator, shares: []const []const u8) !KeyShares {
        if (shares.len == 0) return error.InvalidShareFormat;
        var points = try allocator.alloc(Point, shares.len);
        errdefer allocator.free(points);

        var threshold: usize = 0;
        var integrity: [8]u8 = [_]u8{0} ** 8;

        for (shares, 0..) |share, idx| {
            var it = std.mem.splitScalar(u8, share, '.');
            const x_part = it.next() orelse return error.InvalidShareFormat;
            const y_part = it.next() orelse return error.InvalidShareFormat;
            const t_part = it.next() orelse return error.InvalidShareFormat;
            const i_part = it.next() orelse return error.InvalidShareFormat;
            if (it.next() != null) return error.InvalidShareFormat;

            const tmp = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ x_part, y_part });
            defer allocator.free(tmp);
            const point = try Point.fromString(allocator, tmp);
            points[idx] = point;

            const t_val = try std.fmt.parseUnsigned(usize, t_part, 10);
            if (idx == 0) {
                threshold = t_val;
                if (i_part.len != 8) return error.InvalidShareFormat;
                @memcpy(&integrity, i_part);
            } else {
                if (threshold != t_val) return error.InvalidThreshold;
                if (!std.mem.eql(u8, integrity[0..], i_part)) return error.IntegrityMismatch;
            }
        }
        return .{ .points = points, .threshold = threshold, .integrity = integrity };
    }
};

fn bytesToU256(bytes: []const u8) u256 {
    var buf: [32]u8 = [_]u8{0} ** 32;
    if (bytes.len > 32) {
        @memcpy(buf[0..32], bytes[bytes.len - 32 ..]);
    } else if (bytes.len > 0) {
        @memcpy(buf[32 - bytes.len ..], bytes);
    }
    return std.mem.readInt(u256, &buf, .big);
}

fn u256ToBytes(value: u256) [32]u8 {
    var out: [32]u8 = undefined;
    std.mem.writeInt(u256, &out, value, .big);
    return out;
}

fn trimLeadingZeros(bytes: *const [32]u8) []const u8 {
    var idx: usize = 0;
    while (idx < bytes.len and bytes[idx] == 0) : (idx += 1) {}
    return bytes[idx..];
}

fn modReduce(a: u256) u256 {
    return @intCast(@as(u512, a) % @as(u512, Curve.p));
}

fn modAdd(a: u256, b: u256) u256 {
    const sum = a + b;
    if (sum < a or sum >= Curve.p) return sum - Curve.p;
    return sum;
}

fn modSub(a: u256, b: u256) u256 {
    if (a >= b) return a - b;
    return Curve.p - (b - a);
}

fn modMul(a: u256, b: u256) u256 {
    const prod: u512 = std.math.mulWide(u256, a, b);
    return @intCast(prod % @as(u512, Curve.p));
}

fn modPow(base: u256, exp: u256) u256 {
    var result: u256 = 1;
    var b = modReduce(base);
    var e = exp;
    while (e != 0) : (e >>= 1) {
        if ((e & 1) == 1) result = modMul(result, b);
        b = modMul(b, b);
    }
    return result;
}

fn modInv(a: u256) u256 {
    if (a == 0) return 0;
    return modPow(a, Curve.p - 2);
}

test "polynomial valueAt reconstructs constant term" {
    var points = [_]Point{
        Point.new(0, 42),
        Point.new(1, 7),
        Point.new(2, 9),
    };
    const poly = Polynomial{ .points = points[0..], .threshold = 3 };
    try std.testing.expectEqual(@as(u256, 42), poly.valueAt(0));
}

test "keyshare backup format roundtrips coordinates" {
    const allocator = std.testing.allocator;
    const integrity: [8]u8 = .{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const pts_buf = [_]Point{
        Point.new(1, 42),
        Point.new(2, 9),
    };
    const pts = try allocator.dupe(Point, &pts_buf);
    defer allocator.free(pts);
    const ks = KeyShares{ .points = pts, .threshold = 2, .integrity = integrity };
    const lines = try ks.toBackupFormat(allocator);
    defer {
        for (lines) |s| allocator.free(s);
        allocator.free(lines);
    }
    const back = try KeyShares.fromBackupFormat(allocator, lines);
    defer allocator.free(back.points);
    try std.testing.expectEqual(@as(usize, 2), back.threshold);
    try std.testing.expectEqualSlices(u8, &integrity, &back.integrity);
    for (pts_buf, 0..) |p, i| {
        try std.testing.expectEqual(p.x, back.points[i].x);
        try std.testing.expectEqual(p.y, back.points[i].y);
    }
}
