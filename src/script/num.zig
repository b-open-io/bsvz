const std = @import("std");
const big = std.math.big.int;

pub const Error = error{
    Overflow,
    InvalidEncoding,
    NonMinimalEncoding,
    OutOfMemory,
};

pub const ScriptNum = union(enum) {
    small: i64,
    big: big.Managed,

    pub fn fromInt(value: i64) ScriptNum {
        return .{ .small = value };
    }

    pub fn fromValue(allocator: std.mem.Allocator, value: anytype) !ScriptNum {
        const T = @TypeOf(value);
        switch (@typeInfo(T)) {
            .int, .comptime_int => {
                if (std.math.cast(i64, value)) |small| return .{ .small = small };
                return .{ .big = try big.Managed.initSet(allocator, value) };
            },
            else => {
                if (T == ScriptNum) {
                    return value.clone(allocator);
                }
                @compileError("unsupported ScriptNum source type: " ++ @typeName(T));
            },
        }
    }

    pub fn clone(self: *const ScriptNum, allocator: std.mem.Allocator) !ScriptNum {
        return switch (self.*) {
            .small => |value| .{ .small = value },
            .big => |value| .{ .big = try value.cloneWithDifferentAllocator(allocator) },
        };
    }

    pub fn deinit(self: *ScriptNum) void {
        switch (self.*) {
            .small => {},
            .big => |*value| value.deinit(),
        }
        self.* = .{ .small = 0 };
    }

    pub fn decodeOwned(allocator: std.mem.Allocator, bytes: []const u8) Error!ScriptNum {
        return decodeInternal(allocator, bytes, false);
    }

    pub fn decodeMinimalOwned(allocator: std.mem.Allocator, bytes: []const u8) Error!ScriptNum {
        return decodeInternal(allocator, bytes, true);
    }

    pub fn encode(allocator: std.mem.Allocator, value: anytype) ![]u8 {
        var script_num = try fromValue(allocator, value);
        defer script_num.deinit();
        return script_num.encodeOwned(allocator);
    }

    pub fn encodeOwned(self: *const ScriptNum, allocator: std.mem.Allocator) ![]u8 {
        const negative = self.isNegative();
        const magnitude = try self.magnitudeBytes(allocator);
        defer allocator.free(magnitude);

        if (magnitude.len == 0) return allocator.alloc(u8, 0);

        const needs_extra = (magnitude[magnitude.len - 1] & 0x80) != 0;
        const len = magnitude.len + @intFromBool(needs_extra);
        var out = try allocator.alloc(u8, len);
        @memcpy(out[0..magnitude.len], magnitude);

        if (needs_extra) {
            out[len - 1] = if (negative) 0x80 else 0x00;
        } else if (negative) {
            out[len - 1] |= 0x80;
        }

        return out;
    }

    pub fn num2bin(allocator: std.mem.Allocator, value: anytype, size: usize) ![]u8 {
        var script_num = try fromValue(allocator, value);
        defer script_num.deinit();
        return script_num.num2binOwned(allocator, size);
    }

    pub fn num2binOwned(self: *const ScriptNum, allocator: std.mem.Allocator, size: usize) ![]u8 {
        if (size == 0) {
            if (self.isZero()) return allocator.alloc(u8, 0);
            return error.InvalidEncoding;
        }

        const magnitude = try self.magnitudeBytes(allocator);
        defer allocator.free(magnitude);

        if (magnitude.len > size) return error.InvalidEncoding;
        if (magnitude.len == size and magnitude.len != 0 and (magnitude[magnitude.len - 1] & 0x80) != 0) {
            return error.InvalidEncoding;
        }

        var out = try allocator.alloc(u8, size);
        @memset(out, 0);
        @memcpy(out[0..magnitude.len], magnitude);
        if (self.isNegative() and !self.isZero()) out[size - 1] |= 0x80;
        return out;
    }

    pub fn bin2num(allocator: std.mem.Allocator, bytes: []const u8) Error!ScriptNum {
        return decodeOwned(allocator, bytes);
    }

    pub fn isZero(self: *const ScriptNum) bool {
        return switch (self.*) {
            .small => |value| value == 0,
            .big => |value| value.eqlZero(),
        };
    }

    pub fn isNegative(self: *const ScriptNum) bool {
        return switch (self.*) {
            .small => |value| value < 0,
            .big => |value| !value.isPositive() and !value.eqlZero(),
        };
    }

    pub fn order(lhs: *const ScriptNum, rhs: *const ScriptNum) std.math.Order {
        return switch (lhs.*) {
            .small => |left_value| switch (rhs.*) {
                .small => |right_value| std.math.order(left_value, right_value),
                .big => |right_value| invertOrder(right_value.toConst().orderAgainstScalar(left_value)),
            },
            .big => |left_value| switch (rhs.*) {
                .small => |right_value| left_value.toConst().orderAgainstScalar(right_value),
                .big => |right_value| left_value.order(right_value),
            },
        };
    }

    pub fn eql(lhs: *const ScriptNum, rhs: *const ScriptNum) bool {
        return order(lhs, rhs) == .eq;
    }

    pub fn toIndex(self: *const ScriptNum) Error!usize {
        return switch (self.*) {
            .small => |value| blk: {
                if (value < 0) return error.InvalidEncoding;
                break :blk std.math.cast(usize, value) orelse error.Overflow;
            },
            .big => |value| blk: {
                if (!value.isPositive() and !value.eqlZero()) return error.InvalidEncoding;
                break :blk value.toInt(usize) catch return error.Overflow;
            },
        };
    }

    pub fn negate(self: *const ScriptNum, allocator: std.mem.Allocator) !ScriptNum {
        return switch (self.*) {
            .small => |value| blk: {
                if (value == std.math.minInt(i64)) {
                    var promoted = try big.Managed.initSet(allocator, value);
                    promoted.negate();
                    break :blk normalizeManaged(promoted);
                }
                break :blk .{ .small = -value };
            },
            .big => |value| blk: {
                var out = try value.cloneWithDifferentAllocator(allocator);
                out.negate();
                break :blk normalizeManaged(out);
            },
        };
    }

    pub fn abs(self: *const ScriptNum, allocator: std.mem.Allocator) !ScriptNum {
        return switch (self.*) {
            .small => |value| blk: {
                if (value == std.math.minInt(i64)) {
                    var promoted = try big.Managed.initSet(allocator, value);
                    promoted.abs();
                    break :blk normalizeManaged(promoted);
                }
                break :blk .{ .small = if (value < 0) -value else value };
            },
            .big => |value| blk: {
                var out = try value.cloneWithDifferentAllocator(allocator);
                out.abs();
                break :blk normalizeManaged(out);
            },
        };
    }

    pub fn add(lhs: *const ScriptNum, rhs: *const ScriptNum, allocator: std.mem.Allocator) !ScriptNum {
        return smallBinaryOp(lhs, rhs, .add, allocator) orelse try bigBinaryOp(lhs, rhs, .add, allocator);
    }

    pub fn sub(lhs: *const ScriptNum, rhs: *const ScriptNum, allocator: std.mem.Allocator) !ScriptNum {
        return smallBinaryOp(lhs, rhs, .sub, allocator) orelse try bigBinaryOp(lhs, rhs, .sub, allocator);
    }

    pub fn mul(lhs: *const ScriptNum, rhs: *const ScriptNum, allocator: std.mem.Allocator) !ScriptNum {
        return smallBinaryOp(lhs, rhs, .mul, allocator) orelse try bigBinaryOp(lhs, rhs, .mul, allocator);
    }

    pub fn divTrunc(lhs: *const ScriptNum, rhs: *const ScriptNum, allocator: std.mem.Allocator) !ScriptNum {
        return smallBinaryOp(lhs, rhs, .div_trunc, allocator) orelse try bigBinaryOp(lhs, rhs, .div_trunc, allocator);
    }

    pub fn mod(lhs: *const ScriptNum, rhs: *const ScriptNum, allocator: std.mem.Allocator) !ScriptNum {
        return smallBinaryOp(lhs, rhs, .mod_floor, allocator) orelse try bigBinaryOp(lhs, rhs, .mod_floor, allocator);
    }

    fn decodeInternal(allocator: std.mem.Allocator, bytes: []const u8, require_minimal: bool) Error!ScriptNum {
        if (bytes.len == 0) return .{ .small = 0 };
        if (require_minimal and !isMinimallyEncoded(bytes)) return error.NonMinimalEncoding;

        const last = bytes.len - 1;
        const negative = (bytes[last] & 0x80) != 0;
        const magnitude_zero = blk: {
            for (bytes, 0..) |byte, index| {
                const part: u8 = if (index == last) (byte & 0x7f) else byte;
                if (part != 0) break :blk false;
            }
            break :blk true;
        };
        if (magnitude_zero) return .{ .small = 0 };

        if (bytes.len <= 8) {
            var magnitude: u64 = 0;
            for (bytes, 0..) |byte, index| {
                const part: u8 = if (index == last) (byte & 0x7f) else byte;
                magnitude |= @as(u64, part) << @intCast(index * 8);
            }

            if (!negative) {
                if (std.math.cast(i64, magnitude)) |small| return .{ .small = small };
            } else {
                if (magnitude <= @as(u64, std.math.maxInt(i64))) {
                    return .{ .small = -@as(i64, @intCast(magnitude)) };
                }
            }
        }

        const magnitude_bytes = try allocator.dupe(u8, bytes);
        defer allocator.free(magnitude_bytes);
        magnitude_bytes[last] &= 0x7f;

        var managed = try big.Managed.init(allocator);
        errdefer managed.deinit();
        try managed.ensureCapacity(big.calcTwosCompLimbCount(magnitude_bytes.len * 8));
        var mutable = managed.toMutable();
        mutable.readTwosComplement(magnitude_bytes, magnitude_bytes.len * 8, .little, .unsigned);
        managed.setMetadata(mutable.positive, mutable.len);
        if (negative) managed.negate();
        return normalizeManaged(managed);
    }

    fn magnitudeBytes(self: *const ScriptNum, allocator: std.mem.Allocator) ![]u8 {
        return switch (self.*) {
            .small => |value| encodeMagnitudeSmall(allocator, value),
            .big => |value| encodeMagnitudeBig(allocator, value),
        };
    }

    fn normalizeManaged(managed: big.Managed) !ScriptNum {
        if (managed.eqlZero()) {
            var tmp = managed;
            tmp.deinit();
            return .{ .small = 0 };
        }
        if (managed.fits(i64)) {
            const value = managed.toInt(i64) catch unreachable;
            var tmp = managed;
            tmp.deinit();
            return .{ .small = value };
        }
        return .{ .big = managed };
    }

    fn encodeMagnitudeSmall(allocator: std.mem.Allocator, value: i64) ![]u8 {
        if (value == 0) return allocator.alloc(u8, 0);

        const magnitude_value: u128 = if (value < 0)
            @as(u128, @intCast(-@as(i128, value)))
        else
            @as(u128, @intCast(value));
        return encodeMagnitudeUnsigned(allocator, magnitude_value);
    }

    fn encodeMagnitudeUnsigned(allocator: std.mem.Allocator, magnitude_value: u128) ![]u8 {
        var magnitude = magnitude_value;
        var tmp: [16]u8 = [_]u8{0} ** 16;
        var len: usize = 0;
        while (magnitude != 0) {
            tmp[len] = @truncate(magnitude & 0xff);
            magnitude >>= 8;
            len += 1;
        }

        const out = try allocator.alloc(u8, len);
        @memcpy(out, tmp[0..len]);
        return out;
    }

    fn encodeMagnitudeBig(allocator: std.mem.Allocator, value: big.Managed) ![]u8 {
        if (value.eqlZero()) return allocator.alloc(u8, 0);

        var abs_value = try value.cloneWithDifferentAllocator(allocator);
        defer abs_value.deinit();
        abs_value.abs();

        const byte_len = @max((abs_value.bitCountAbs() + 7) / 8, 1);
        const out = try allocator.alloc(u8, byte_len);
        @memset(out, 0);
        abs_value.toConst().writeTwosComplement(out, .little);
        return out;
    }

    fn isMinimallyEncoded(bytes: []const u8) bool {
        if (bytes.len == 0) return true;
        if ((bytes[bytes.len - 1] & 0x7f) != 0) return true;
        if (bytes.len == 1) return false;
        return (bytes[bytes.len - 2] & 0x80) != 0;
    }

    const BinaryOp = enum {
        add,
        sub,
        mul,
        div_trunc,
        mod_floor,
    };

    fn smallBinaryOp(lhs: *const ScriptNum, rhs: *const ScriptNum, op: BinaryOp, allocator: std.mem.Allocator) ?ScriptNum {
        _ = allocator;
        const left = switch (lhs.*) {
            .small => |value| value,
            .big => return null,
        };
        const right = switch (rhs.*) {
            .small => |value| value,
            .big => return null,
        };

        return switch (op) {
            .add => blk: {
                const result = @addWithOverflow(left, right);
                if (result[1] != 0) return null;
                break :blk .{ .small = result[0] };
            },
            .sub => blk: {
                const result = @subWithOverflow(left, right);
                if (result[1] != 0) return null;
                break :blk .{ .small = result[0] };
            },
            .mul => blk: {
                const result = @mulWithOverflow(left, right);
                if (result[1] != 0) return null;
                break :blk .{ .small = result[0] };
            },
            .div_trunc => blk: {
                if (right == 0) return null;
                break :blk .{ .small = @divTrunc(left, right) };
            },
            .mod_floor => blk: {
                if (right == 0) return null;
                break :blk .{ .small = @mod(left, right) };
            },
        };
    }

    fn bigBinaryOp(lhs: *const ScriptNum, rhs: *const ScriptNum, op: BinaryOp, allocator: std.mem.Allocator) !ScriptNum {
        var left = try lhs.toManaged(allocator);
        defer left.deinit();
        var right = try rhs.toManaged(allocator);
        defer right.deinit();

        if (right.eqlZero() and (op == .div_trunc or op == .mod_floor)) return error.InvalidEncoding;

        var result = try big.Managed.init(allocator);
        errdefer result.deinit();

        switch (op) {
            .add => try result.add(&left, &right),
            .sub => try result.sub(&left, &right),
            .mul => try result.mul(&left, &right),
            .div_trunc => {
                var remainder = try big.Managed.init(allocator);
                defer remainder.deinit();
                try result.divTrunc(&remainder, &left, &right);
            },
            .mod_floor => {
                var quotient = try big.Managed.init(allocator);
                defer quotient.deinit();
                try quotient.divFloor(&result, &left, &right);
            },
        }

        return normalizeManaged(result);
    }

    fn toManaged(self: *const ScriptNum, allocator: std.mem.Allocator) !big.Managed {
        return switch (self.*) {
            .small => |value| big.Managed.initSet(allocator, value),
            .big => |value| value.cloneWithDifferentAllocator(allocator),
        };
    }

    fn invertOrder(ord: std.math.Order) std.math.Order {
        return switch (ord) {
            .lt => .gt,
            .eq => .eq,
            .gt => .lt,
        };
    }
};

test "script num roundtrip for positive and negative values" {
    const allocator = std.testing.allocator;

    for ([_]i64{
        0,
        1,
        -1,
        16,
        -16,
        17,
        -17,
        127,
        -127,
        128,
        -128,
        255,
        -255,
        256,
        -256,
        32767,
        -32767,
        32768,
        -32768,
        std.math.maxInt(i32),
        std.math.minInt(i32),
    }) |value| {
        const encoded = try ScriptNum.encode(allocator, value);
        defer allocator.free(encoded);

        var decoded = try ScriptNum.decodeOwned(allocator, encoded);
        defer decoded.deinit();
        try std.testing.expect(decoded.eql(&ScriptNum.fromInt(value)));

        var decoded_min = try ScriptNum.decodeMinimalOwned(allocator, encoded);
        defer decoded_min.deinit();
        try std.testing.expect(decoded_min.eql(&ScriptNum.fromInt(value)));
    }
}

test "script num promotes large values beyond i64" {
    const allocator = std.testing.allocator;
    const encoded = &[_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x01 };

    var decoded = try ScriptNum.decodeOwned(allocator, encoded);
    defer decoded.deinit();

    switch (decoded) {
        .small => return error.TestUnexpectedResult,
        .big => {},
    }

    const roundtrip = try decoded.encodeOwned(allocator);
    defer allocator.free(roundtrip);
    try std.testing.expectEqualSlices(u8, encoded, roundtrip);
}

test "num2bin and bin2num roundtrip" {
    const allocator = std.testing.allocator;
    const encoded = try ScriptNum.num2bin(allocator, 300, 2);
    defer allocator.free(encoded);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x2c, 0x01 }, encoded);
    var decoded = try ScriptNum.bin2num(allocator, encoded);
    defer decoded.deinit();
    try std.testing.expect(decoded.eql(&ScriptNum.fromInt(300)));
}

test "num2bin keeps the sign bit in the final byte" {
    const allocator = std.testing.allocator;
    const encoded = try ScriptNum.num2bin(allocator, -1, 2);
    defer allocator.free(encoded);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x80 }, encoded);
}

test "decodeMinimal rejects negative zero" {
    try std.testing.expectError(error.NonMinimalEncoding, ScriptNum.decodeMinimalOwned(std.testing.allocator, &[_]u8{0x80}));
}

test "decodeMinimal rejects redundant sign padding" {
    try std.testing.expectError(error.NonMinimalEncoding, ScriptNum.decodeMinimalOwned(std.testing.allocator, &[_]u8{ 0x01, 0x00 }));
    try std.testing.expectError(error.NonMinimalEncoding, ScriptNum.decodeMinimalOwned(std.testing.allocator, &[_]u8{ 0x01, 0x80 }));
}

test "num2bin rejects undersized non-zero encodings" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidEncoding, ScriptNum.num2bin(allocator, 128, 1));
    try std.testing.expectError(error.InvalidEncoding, ScriptNum.num2bin(allocator, -128, 1));
}

test "num2bin and bin2num match representative go-sdk operation semantics" {
    const allocator = std.testing.allocator;

    {
        const encoded = try ScriptNum.num2bin(allocator, 0, 0);
        defer allocator.free(encoded);
        try std.testing.expectEqualSlices(u8, &.{}, encoded);
    }

    {
        const encoded = try ScriptNum.num2bin(allocator, -1, 2);
        defer allocator.free(encoded);
        try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x80 }, encoded);
    }

    {
        const encoded = try ScriptNum.num2bin(allocator, 128, 2);
        defer allocator.free(encoded);
        try std.testing.expectEqualSlices(u8, &.{ 0x80, 0x00 }, encoded);
    }

    {
        var decoded = try ScriptNum.bin2num(allocator, &.{ 0x80 });
        defer decoded.deinit();
        try std.testing.expect(decoded.isZero());
        const reencoded = try decoded.encodeOwned(allocator);
        defer allocator.free(reencoded);
        try std.testing.expectEqualSlices(u8, &.{}, reencoded);
    }

    {
        var decoded = try ScriptNum.bin2num(allocator, &.{ 0x01, 0x00 });
        defer decoded.deinit();
        const reencoded = try decoded.encodeOwned(allocator);
        defer allocator.free(reencoded);
        try std.testing.expectEqualSlices(u8, &.{0x01}, reencoded);
    }

    {
        var decoded = try ScriptNum.bin2num(allocator, &.{ 0x01, 0x80 });
        defer decoded.deinit();
        const reencoded = try decoded.encodeOwned(allocator);
        defer allocator.free(reencoded);
        try std.testing.expectEqualSlices(u8, &.{0x81}, reencoded);
    }
}

test "script num matches representative go-sdk encode/decode vectors" {
    const allocator = std.testing.allocator;

    const Case = struct {
        value: i128,
        encoded: []const u8,
    };

    const cases = [_]Case{
        .{ .value = 0, .encoded = &.{} },
        .{ .value = 1, .encoded = &.{0x01} },
        .{ .value = -1, .encoded = &.{0x81} },
        .{ .value = 127, .encoded = &.{0x7f} },
        .{ .value = -127, .encoded = &.{0xff} },
        .{ .value = 128, .encoded = &.{ 0x80, 0x00 } },
        .{ .value = -128, .encoded = &.{ 0x80, 0x80 } },
        .{ .value = 129, .encoded = &.{ 0x81, 0x00 } },
        .{ .value = -129, .encoded = &.{ 0x81, 0x80 } },
        .{ .value = 32767, .encoded = &.{ 0xff, 0x7f } },
        .{ .value = -32767, .encoded = &.{ 0xff, 0xff } },
        .{ .value = 32768, .encoded = &.{ 0x00, 0x80, 0x00 } },
        .{ .value = -32768, .encoded = &.{ 0x00, 0x80, 0x80 } },
        .{ .value = 2147483647, .encoded = &.{ 0xff, 0xff, 0xff, 0x7f } },
        .{ .value = -2147483647, .encoded = &.{ 0xff, 0xff, 0xff, 0xff } },
        .{ .value = 2147483648, .encoded = &.{ 0x00, 0x00, 0x00, 0x80, 0x00 } },
        .{ .value = -2147483648, .encoded = &.{ 0x00, 0x00, 0x00, 0x80, 0x80 } },
        .{ .value = 4294967296, .encoded = &.{ 0x00, 0x00, 0x00, 0x00, 0x01 } },
        .{ .value = -4294967296, .encoded = &.{ 0x00, 0x00, 0x00, 0x00, 0x81 } },
    };

    inline for (cases) |case| {
        const encoded = try ScriptNum.encode(allocator, case.value);
        defer allocator.free(encoded);
        try std.testing.expectEqualSlices(u8, case.encoded, encoded);

        var decoded = try ScriptNum.decodeOwned(allocator, case.encoded);
        defer decoded.deinit();
        var expected = try ScriptNum.fromValue(allocator, case.value);
        defer expected.deinit();
        try std.testing.expect(decoded.eql(&expected));

        var decoded_min = try ScriptNum.decodeMinimalOwned(allocator, case.encoded);
        defer decoded_min.deinit();
        try std.testing.expect(decoded_min.eql(&expected));
    }
}
