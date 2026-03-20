const std = @import("std");
const crypto = @import("../crypto/lib.zig");
const primitives = @import("../primitives/lib.zig");
const MerkleTreeParent = @import("merkle_tree_parent.zig").MerkleTreeParent;

pub const PathElement = struct {
    offset: u64,
    hash: ?crypto.Hash256 = null,
    txid: ?bool = null,
    duplicate: ?bool = null,
};

pub const MerklePath = struct {
    block_height: u32,
    path: [][]PathElement,

    pub fn parse(allocator: std.mem.Allocator, data: []const u8) !MerklePath {
        var cursor: usize = 0;
        return parseFromCursor(allocator, data, &cursor);
    }

    pub fn parseFromCursor(
        allocator: std.mem.Allocator,
        data: []const u8,
        cursor: *usize,
    ) !MerklePath {
        const index = try primitives.varint.VarInt.parse(data[cursor.* ..]);
        cursor.* += index.len;
        const block_height = std.math.cast(u32, index.value) orelse return error.Overflow;

        if (data.len < cursor.* + 1) return error.EndOfStream;
        const tree_height = data[cursor.*];
        cursor.* += 1;

        var levels = try allocator.alloc([]PathElement, tree_height);
        errdefer allocator.free(levels);

        var level: usize = 0;
        while (level < tree_height) : (level += 1) {
            const count = try primitives.varint.VarInt.parse(data[cursor.* ..]);
            cursor.* += count.len;
            const leaf_count = std.math.cast(usize, count.value) orelse return error.Overflow;
            var leaves = try allocator.alloc(PathElement, leaf_count);
            errdefer allocator.free(leaves);

            var leaf_index: usize = 0;
            while (leaf_index < leaf_count) : (leaf_index += 1) {
                const offset_var = try primitives.varint.VarInt.parse(data[cursor.* ..]);
                cursor.* += offset_var.len;
                const offset = offset_var.value;
                if (data.len < cursor.* + 1) return error.EndOfStream;
                const flags = data[cursor.*];
                cursor.* += 1;

                const dup = (flags & 1) != 0;
                const txid_flag = (flags & 2) != 0;
                var hash: ?crypto.Hash256 = null;
                if (!dup) {
                    if (data.len < cursor.* + 32) return error.EndOfStream;
                    var h: [32]u8 = undefined;
                    @memcpy(&h, data[cursor.* .. cursor.* + 32]);
                    hash = .{ .bytes = h };
                    cursor.* += 32;
                }

                leaves[leaf_index] = .{
                    .offset = offset,
                    .hash = hash,
                    .duplicate = if (dup) true else null,
                    .txid = if (txid_flag) true else null,
                };
            }

            std.sort.insertion(PathElement, leaves, {}, struct {
                fn lessThan(_: void, a: PathElement, b: PathElement) bool {
                    return a.offset < b.offset;
                }
            }.lessThan);

            levels[level] = leaves;
        }

        return .{
            .block_height = block_height,
            .path = levels,
        };
    }

    pub fn bytes(self: *const MerklePath, allocator: std.mem.Allocator) ![]u8 {
        var out = std.ArrayList(u8).initCapacity(allocator, 64) catch return error.OutOfMemory;
        defer out.deinit(allocator);

        var buf: [9]u8 = undefined;
        const height_len = try primitives.varint.VarInt.encodeInto(&buf, self.block_height);
        try out.appendSlice(allocator, buf[0..height_len]);
        try out.append(allocator, @intCast(self.path.len));

        for (self.path) |level| {
            const leaf_len = try primitives.varint.VarInt.encodeInto(&buf, level.len);
            try out.appendSlice(allocator, buf[0..leaf_len]);
            for (level) |leaf| {
                const off_len = try primitives.varint.VarInt.encodeInto(&buf, leaf.offset);
                try out.appendSlice(allocator, buf[0..off_len]);
                var flags: u8 = 0;
                if (leaf.duplicate) |dup| {
                    if (dup) flags |= 1;
                }
                if (leaf.txid) |flag| {
                    if (flag) flags |= 2;
                }
                try out.append(allocator, flags);
                if ((flags & 1) == 0) {
                    const hash = leaf.hash orelse return error.InvalidEncoding;
                    try out.appendSlice(allocator, hash.bytes[0..]);
                }
            }
        }
        return out.toOwnedSlice(allocator);
    }

    pub fn clone(self: *const MerklePath, allocator: std.mem.Allocator) !MerklePath {
        const levels = try allocator.alloc([]PathElement, self.path.len);
        var done: usize = 0;
        errdefer {
            for (0..done) |j| allocator.free(levels[j]);
            allocator.free(levels);
        }
        for (self.path, 0..) |level, index| {
            levels[index] = try allocator.dupe(PathElement, level);
            done += 1;
        }
        return .{
            .block_height = self.block_height,
            .path = levels,
        };
    }

    pub fn deinit(self: *MerklePath, allocator: std.mem.Allocator) void {
        for (self.path) |level| allocator.free(level);
        if (self.path.len > 0) allocator.free(self.path);
        self.* = .{
            .block_height = 0,
            .path = &.{},
        };
    }

    pub fn computeRoot(self: *const MerklePath, allocator: std.mem.Allocator, txid: ?crypto.Hash256) !crypto.Hash256 {
        if (self.path.len == 0) return error.InvalidEncoding;
        var target = txid;
        if (target == null) {
            for (self.path[0]) |leaf| {
                if (leaf.hash != null) {
                    target = leaf.hash;
                    break;
                }
            }
        }
        const root_txid = target orelse return error.InvalidEncoding;
        if (self.path.len == 1 and self.path[0].len == 1) return root_txid;

        var indexed = try std.ArrayList(std.AutoHashMap(u64, PathElement)).initCapacity(allocator, self.path.len);
        defer {
            for (indexed.items) |*map| map.deinit();
            indexed.deinit(allocator);
        }
        for (self.path) |level| {
            var map = std.AutoHashMap(u64, PathElement).init(allocator);
            for (level) |leaf| {
                try map.put(leaf.offset, leaf);
            }
            try indexed.append(allocator, map);
        }

        var tx_leaf: ?PathElement = null;
        for (self.path[0]) |leaf| {
            if (leaf.hash) |h| {
                if (std.mem.eql(u8, &h.bytes, &root_txid.bytes)) {
                    tx_leaf = leaf;
                    break;
                }
            }
        }
        const leaf = tx_leaf orelse return error.InvalidEncoding;
        var working = leaf.hash orelse return error.InvalidEncoding;
        const index = leaf.offset;

        var height: usize = 0;
        while (height < self.path.len) : (height += 1) {
            const offset = (index >> @intCast(height)) ^ 1;
            const sibling = getOffsetLeaf(indexed.items, height, offset) orelse return error.InvalidEncoding;
            if (sibling.duplicate) |dup| {
                if (dup) {
                    working = MerkleTreeParent(working, working);
                    continue;
                }
            }
            const sibling_hash = sibling.hash orelse return error.InvalidEncoding;
            if ((offset & 1) != 0) {
                working = MerkleTreeParent(working, sibling_hash);
            } else {
                working = MerkleTreeParent(sibling_hash, working);
            }
        }
        return working;
    }

    pub fn verify(
        self: *const MerklePath,
        allocator: std.mem.Allocator,
        txid: ?crypto.Hash256,
        chain_tracker: anytype,
    ) !bool {
        const root = try self.computeRoot(allocator, txid);
        return chain_tracker.isValidRootForHeight(root, self.block_height);
    }

    pub fn findLeafByOffset(self: *const MerklePath, level: usize, offset: u64) ?*const PathElement {
        if (level >= self.path.len) return null;
        for (self.path[level]) |*leaf| {
            if (leaf.offset == offset) return leaf;
        }
        return null;
    }

    pub fn addLeaf(
        self: *MerklePath,
        allocator: std.mem.Allocator,
        level: usize,
        element: PathElement,
    ) !void {
        if (level >= self.path.len) {
            const old_len = self.path.len;
            if (self.path.len == 0) {
                self.path = try allocator.alloc([]PathElement, level + 1);
            } else {
                self.path = try allocator.realloc(self.path, level + 1);
            }
            for (self.path[old_len .. level + 1]) |*new_level| new_level.* = &.{};
        }

        const old_level = self.path[level];
        var new_level = try allocator.alloc(PathElement, old_level.len + 1);
        if (old_level.len > 0) @memcpy(new_level[0..old_level.len], old_level);
        new_level[old_level.len] = element;
        if (old_level.len > 0) allocator.free(old_level);
        std.sort.insertion(PathElement, new_level, {}, pathElementLessThan);
        self.path[level] = new_level;
    }

    pub fn computeMissingHashes(self: *MerklePath, allocator: std.mem.Allocator) !void {
        if (self.path.len < 2) return;

        var level: usize = 1;
        while (level < self.path.len) : (level += 1) {
            const prev_level = self.path[level - 1];
            for (prev_level) |left_leaf| {
                if (left_leaf.hash == null or (left_leaf.offset & 1) != 0) continue;

                const right_offset = left_leaf.offset + 1;
                const right_leaf = self.findLeafByOffset(level - 1, right_offset);
                const parent_offset = left_leaf.offset >> 1;

                if (self.findLeafByOffset(level, parent_offset) != null) continue;

                if (right_leaf) |right| {
                    var parent = PathElement{ .offset = parent_offset };
                    if (right.hash) |right_hash| {
                        parent.hash = MerkleTreeParent(left_leaf.hash.?, right_hash);
                    } else if (right.duplicate) |dup| {
                        if (dup) parent.hash = MerkleTreeParent(left_leaf.hash.?, left_leaf.hash.?);
                    }
                    if (parent.hash != null) try self.addLeaf(allocator, level, parent);
                }
            }
        }
    }

    pub fn combine(self: *MerklePath, other: *const MerklePath, allocator: std.mem.Allocator) !void {
        if (self.block_height != other.block_height) return error.InvalidEncoding;
        if (self.path.len != other.path.len) return error.InvalidEncoding;
        const root_a = try self.computeRoot(allocator, null);
        const root_b = try other.computeRoot(allocator, null);
        if (!std.mem.eql(u8, &root_a.bytes, &root_b.bytes)) return error.InvalidEncoding;

        var combined = try allocator.alloc(std.AutoHashMap(u64, PathElement), self.path.len);
        defer {
            for (combined) |*map| map.deinit();
            allocator.free(combined);
        }
        for (self.path, 0..) |level, idx| {
            combined[idx] = std.AutoHashMap(u64, PathElement).init(allocator);
            for (level) |leaf| {
                _ = try combined[idx].put(leaf.offset, leaf);
            }
        }
        for (other.path, 0..) |level, idx| {
            for (level) |leaf| {
                _ = try combined[idx].put(leaf.offset, leaf);
            }
        }

        const new_levels = try allocator.alloc([]PathElement, self.path.len);
        errdefer allocator.free(new_levels);

        var idx = self.path.len;
        while (idx > 0) {
            idx -= 1;
            var new_level = std.ArrayList(PathElement).initCapacity(allocator, combined[idx].count()) catch return error.OutOfMemory;
            defer new_level.deinit(allocator);
            var it = combined[idx].iterator();
            while (it.next()) |entry| {
                if (idx > 0) {
                    const child_offset = entry.key_ptr.* * 2;
                    if (combined[idx - 1].contains(child_offset) and combined[idx - 1].contains(child_offset + 1)) {
                        continue;
                    }
                }
                try new_level.append(allocator, entry.value_ptr.*);
            }
            new_levels[idx] = try new_level.toOwnedSlice(allocator);
            std.sort.insertion(PathElement, new_levels[idx], {}, pathElementLessThan);
        }

        for (self.path) |level| allocator.free(level);
        if (self.path.len > 0) allocator.free(self.path);
        self.path = new_levels;
    }
};

fn pathElementLessThan(_: void, a: PathElement, b: PathElement) bool {
    return a.offset < b.offset;
}

fn getOffsetLeaf(
    levels: []std.AutoHashMap(u64, PathElement),
    layer: usize,
    offset: u64,
) ?PathElement {
    if (levels[layer].get(offset)) |leaf| return leaf;
    if (layer == 0) return null;
    const left = getOffsetLeaf(levels, layer - 1, offset * 2);
    const right = getOffsetLeaf(levels, layer - 1, offset * 2 + 1);
    if (left == null or right == null) return null;
    const l = left.?;
    const r = right.?;
    var out = PathElement{ .offset = offset };
    if (r.duplicate) |dup| {
        if (dup) {
            out.hash = MerkleTreeParent(l.hash.?, l.hash.?);
            return out;
        }
    }
    out.hash = MerkleTreeParent(l.hash.?, r.hash.?);
    return out;
}

test "merkle path clone and combine keep owned copies" {
    const allocator = std.testing.allocator;
    const txid_a = crypto.Hash256{ .bytes = [_]u8{0x11} ** 32 };
    const txid_b = crypto.Hash256{ .bytes = [_]u8{0x22} ** 32 };

    var path_a = MerklePath{
        .block_height = 10,
        .path = try allocator.alloc([]PathElement, 1),
    };
    defer path_a.deinit(allocator);
    path_a.path[0] = try allocator.alloc(PathElement, 2);
    path_a.path[0][0] = .{ .offset = 0, .hash = txid_a, .txid = true };
    path_a.path[0][1] = .{ .offset = 1, .hash = txid_b };

    var path_b = try path_a.clone(allocator);
    defer path_b.deinit(allocator);
    path_b.path[0][1].txid = true;

    try path_a.combine(&path_b, allocator);
    try std.testing.expect(path_a.path[0].len == 2);
    try std.testing.expect(path_a.path[0][1].txid != null);
}

test "merkle path computes missing hashes" {
    const allocator = std.testing.allocator;
    const left = crypto.Hash256{ .bytes = [_]u8{0x33} ** 32 };
    const right = crypto.Hash256{ .bytes = [_]u8{0x44} ** 32 };

    var path = MerklePath{
        .block_height = 20,
        .path = try allocator.alloc([]PathElement, 2),
    };
    defer path.deinit(allocator);
    path.path[0] = try allocator.alloc(PathElement, 2);
    path.path[1] = try allocator.alloc(PathElement, 0);
    path.path[0][0] = .{ .offset = 0, .hash = left, .txid = true };
    path.path[0][1] = .{ .offset = 1, .hash = right };

    try path.computeMissingHashes(allocator);
    try std.testing.expectEqual(@as(usize, 1), path.path[1].len);
    try std.testing.expectEqualDeep(MerkleTreeParent(left, right), path.path[1][0].hash.?);
}
