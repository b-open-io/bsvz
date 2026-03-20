const std = @import("std");
const primitives = @import("../primitives/lib.zig");
const txmod = @import("transaction.zig");
const Input = @import("input.zig").Input;
const Output = @import("output.zig").Output;
const MerklePath = @import("../spv/merkle_path.zig").MerklePath;

pub const BEEF_V1: u32 = 4022206465;
pub const BEEF_V2: u32 = 4022206466;
pub const ATOMIC_BEEF: u32 = 0x01010101;

pub const DataFormat = enum(u8) {
    RawTx = 0,
    RawTxAndBumpIndex = 1,
    TxIDOnly = 2,
};

pub const BeefTx = struct {
    data_format: DataFormat,
    known_txid: ?primitives.chainhash.Hash = null,
    transaction: ?txmod.Transaction = null,
    bump_index: ?usize = null,
};

pub const ParsedBeef = struct {
    beef: Beef,
    tx: ?txmod.Transaction,
    txid: ?primitives.chainhash.Hash,

    pub fn deinit(self: *ParsedBeef) void {
        if (self.tx) |tx| tx.deinit(self.beef.allocator);
        self.beef.deinit();
        self.* = .{
            .beef = Beef.init(self.beef.allocator, self.beef.version),
            .tx = null,
            .txid = null,
        };
    }
};

pub const ValidationResult = struct {
    allocator: std.mem.Allocator,
    valid: []primitives.chainhash.Hash,
    not_valid: []primitives.chainhash.Hash,
    txid_only: []primitives.chainhash.Hash,
    with_missing_inputs: []primitives.chainhash.Hash,
    missing_inputs: []primitives.chainhash.Hash,

    pub fn deinit(self: *ValidationResult) void {
        if (self.valid.len > 0) self.allocator.free(self.valid);
        if (self.not_valid.len > 0) self.allocator.free(self.not_valid);
        if (self.txid_only.len > 0) self.allocator.free(self.txid_only);
        if (self.with_missing_inputs.len > 0) self.allocator.free(self.with_missing_inputs);
        if (self.missing_inputs.len > 0) self.allocator.free(self.missing_inputs);
        self.* = .{
            .allocator = self.allocator,
            .valid = &.{},
            .not_valid = &.{},
            .txid_only = &.{},
            .with_missing_inputs = &.{},
            .missing_inputs = &.{},
        };
    }
};

const VerifyResult = struct {
    allocator: std.mem.Allocator,
    valid: bool = false,
    roots: std.AutoHashMap(u32, primitives.chainhash.Hash),

    fn init(allocator: std.mem.Allocator) VerifyResult {
        return .{
            .allocator = allocator,
            .roots = std.AutoHashMap(u32, primitives.chainhash.Hash).init(allocator),
        };
    }

    fn deinit(self: *VerifyResult) void {
        self.roots.deinit();
        self.* = init(self.allocator);
    }
};

pub const Beef = struct {
    allocator: std.mem.Allocator,
    version: u32,
    bumps: []MerklePath,
    transactions: std.AutoHashMap(primitives.chainhash.Hash, BeefTx),

    pub fn init(allocator: std.mem.Allocator, version: u32) Beef {
        return .{
            .allocator = allocator,
            .version = version,
            .bumps = &.{},
            .transactions = std.AutoHashMap(primitives.chainhash.Hash, BeefTx).init(allocator),
        };
    }

    pub fn deinit(self: *Beef) void {
        var it = self.transactions.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.transaction) |tx| tx.deinit(self.allocator);
        }
        self.transactions.deinit();
        for (self.bumps) |*bump| bump.deinit(self.allocator);
        if (self.bumps.len > 0) self.allocator.free(self.bumps);
        self.* = Beef.init(self.allocator, self.version);
    }

    pub fn clone(self: *const Beef, allocator: std.mem.Allocator) !Beef {
        var cloned = Beef.init(allocator, self.version);
        errdefer cloned.deinit();

        cloned.bumps = try allocator.alloc(MerklePath, self.bumps.len);
        for (self.bumps, 0..) |bump, idx| {
            cloned.bumps[idx] = try bump.clone(allocator);
        }

        var it = self.transactions.iterator();
        while (it.next()) |entry| {
            var cloned_entry = BeefTx{
                .data_format = entry.value_ptr.data_format,
                .known_txid = entry.value_ptr.known_txid,
                .bump_index = entry.value_ptr.bump_index,
            };
            if (entry.value_ptr.transaction) |*tx| {
                var cloned_tx = try tx.shallowClone(allocator);
                if (cloned_entry.bump_index) |bump_index| {
                    if (bump_index >= cloned.bumps.len) return error.InvalidEncoding;
                    cloned_tx.merkle_path = cloned.bumps[bump_index];
                    cloned_tx.owns_merkle_path = false;
                }
                cloned_entry.transaction = cloned_tx;
            }
            try cloned.transactions.put(entry.key_ptr.*, cloned_entry);
        }

        try hydrateInputs(&cloned);

        return cloned;
    }

    pub fn bytes(self: *const Beef) ![]u8 {
        return switch (self.version) {
            BEEF_V1 => self.bytesV1(),
            BEEF_V2 => self.bytesV2(),
            else => error.InvalidEncoding,
        };
    }

    pub fn findTransaction(self: *const Beef, txid: primitives.chainhash.Hash) ?*const txmod.Transaction {
        if (self.transactions.getPtr(txid)) |entry| {
            if (entry.transaction) |*tx| return tx;
        }
        return null;
    }

    pub fn findBumpByHash(self: *const Beef, txid: primitives.chainhash.Hash) ?*const MerklePath {
        if (self.transactions.get(txid)) |entry| {
            if (entry.bump_index) |idx| {
                if (idx < self.bumps.len) return &self.bumps[idx];
            }
        }
        for (self.bumps) |*bump| {
            if (bump.path.len == 0) continue;
            for (bump.path[0]) |leaf| {
                if (leaf.hash) |hash| {
                    if (std.mem.eql(u8, &hash.bytes, &txid.bytes)) return bump;
                }
            }
        }
        return null;
    }

    pub fn findBump(self: *const Beef, txid_hex: []const u8) ?*const MerklePath {
        const txid = primitives.chainhash.Hash.fromHex(txid_hex) catch return null;
        return self.findBumpByHash(txid);
    }

    pub fn hex(self: *const Beef) ![]u8 {
        const raw = try self.bytes();
        defer self.allocator.free(raw);

        const encoded = try self.allocator.alloc(u8, raw.len * 2);
        _ = try primitives.hex.encodeLower(raw, encoded);
        return encoded;
    }

    pub fn validateTransactions(self: *const Beef) !ValidationResult {
        var result = ValidationResult{
            .allocator = self.allocator,
            .valid = &.{},
            .not_valid = &.{},
            .txid_only = &.{},
            .with_missing_inputs = &.{},
            .missing_inputs = &.{},
        };
        errdefer result.deinit();

        const keys = try collectKeys(self.allocator, &self.transactions);
        defer self.allocator.free(keys);

        var txids_in_bumps = std.AutoHashMap(primitives.chainhash.Hash, void).init(self.allocator);
        defer txids_in_bumps.deinit();
        for (self.bumps) |*bump| {
            if (bump.path.len == 0) continue;
            for (bump.path[0]) |leaf| {
                if (leaf.txid != true) continue;
                const hash = leaf.hash orelse continue;
                try txids_in_bumps.put(.{ .bytes = hash.bytes }, {});
            }
        }

        var valid_txids = std.AutoHashMap(primitives.chainhash.Hash, void).init(self.allocator);
        defer valid_txids.deinit();
        var missing_inputs = std.AutoHashMap(primitives.chainhash.Hash, void).init(self.allocator);
        defer missing_inputs.deinit();

        var has_proof: std.ArrayList(primitives.chainhash.Hash) = .empty;
        defer has_proof.deinit(self.allocator);
        var txid_only: std.ArrayList(primitives.chainhash.Hash) = .empty;
        defer txid_only.deinit(self.allocator);
        var needs_validation: std.ArrayList(primitives.chainhash.Hash) = .empty;
        defer needs_validation.deinit(self.allocator);
        var with_missing_inputs: std.ArrayList(primitives.chainhash.Hash) = .empty;
        defer with_missing_inputs.deinit(self.allocator);
        var not_valid: std.ArrayList(primitives.chainhash.Hash) = .empty;
        defer not_valid.deinit(self.allocator);
        var valid: std.ArrayList(primitives.chainhash.Hash) = .empty;
        defer valid.deinit(self.allocator);

        for (keys) |txid| {
            const beef_tx = self.transactions.get(txid) orelse continue;
            switch (beef_tx.data_format) {
                .TxIDOnly => {
                    const known = beef_tx.known_txid orelse txid;
                    try txid_only.append(self.allocator, known);
                    if (txids_in_bumps.contains(known)) {
                        try valid_txids.put(known, {});
                    }
                },
                .RawTxAndBumpIndex => {
                    if (beef_tx.bump_index) |idx| {
                        if (idx < self.bumps.len and txAppearsInBump(&self.bumps[idx], txid)) {
                            try valid_txids.put(txid, {});
                            try has_proof.append(self.allocator, txid);
                        } else {
                            try needs_validation.append(self.allocator, txid);
                        }
                    } else {
                        try needs_validation.append(self.allocator, txid);
                    }
                },
                .RawTx => {
                    if (txids_in_bumps.contains(txid)) {
                        try valid_txids.put(txid, {});
                        try has_proof.append(self.allocator, txid);
                    } else if (beef_tx.transaction) |tx| {
                        var has_missing = false;
                        for (tx.inputs) |input| {
                            const source_txid = primitives.chainhash.Hash{ .bytes = input.previous_outpoint.txid.bytes };
                            if (!self.transactions.contains(source_txid)) {
                                has_missing = true;
                                try missing_inputs.put(source_txid, {});
                            }
                        }
                        if (has_missing) {
                            try with_missing_inputs.append(self.allocator, txid);
                        } else {
                            try needs_validation.append(self.allocator, txid);
                        }
                    }
                },
            }
        }

        while (needs_validation.items.len > 0) {
            var progress = false;
            var next_round: std.ArrayList(primitives.chainhash.Hash) = .empty;
            defer next_round.deinit(self.allocator);

            for (needs_validation.items) |txid| {
                const beef_tx = self.transactions.get(txid) orelse continue;
                const tx = beef_tx.transaction orelse {
                    try not_valid.append(self.allocator, txid);
                    continue;
                };

                var all_inputs_valid = true;
                for (tx.inputs) |input| {
                    const source_txid = primitives.chainhash.Hash{ .bytes = input.previous_outpoint.txid.bytes };
                    if (!valid_txids.contains(source_txid)) {
                        all_inputs_valid = false;
                        break;
                    }
                }

                if (all_inputs_valid) {
                    progress = true;
                    try valid_txids.put(txid, {});
                    try has_proof.append(self.allocator, txid);
                } else {
                    try next_round.append(self.allocator, txid);
                }
            }

            needs_validation.clearRetainingCapacity();
            if (!progress) {
                for (next_round.items) |txid| try not_valid.append(self.allocator, txid);
                break;
            }
            try needs_validation.appendSlice(self.allocator, next_round.items);
        }

        sortHashes(txid_only.items);
        sortHashes(has_proof.items);
        sortHashes(with_missing_inputs.items);
        sortHashes(not_valid.items);

        for (txid_only.items) |txid| {
            if (valid_txids.contains(txid)) try valid.append(self.allocator, txid);
        }
        try valid.appendSlice(self.allocator, has_proof.items);
        sortHashes(valid.items);

        const missing_keys = try collectHashKeys(self.allocator, &missing_inputs);
        defer self.allocator.free(missing_keys);

        result.valid = try valid.toOwnedSlice(self.allocator);
        result.not_valid = try not_valid.toOwnedSlice(self.allocator);
        result.txid_only = try txid_only.toOwnedSlice(self.allocator);
        result.with_missing_inputs = try with_missing_inputs.toOwnedSlice(self.allocator);
        result.missing_inputs = try self.allocator.dupe(primitives.chainhash.Hash, missing_keys);
        return result;
    }

    pub fn isValid(self: *const Beef, allocator: std.mem.Allocator, allow_txid_only: bool) !bool {
        var verification = try self.verifyValid(allocator, allow_txid_only);
        defer verification.deinit();
        return verification.valid;
    }

    pub fn verify(self: *const Beef, allocator: std.mem.Allocator, chain_tracker: anytype, allow_txid_only: bool) !bool {
        var verification = try self.verifyValid(allocator, allow_txid_only);
        defer verification.deinit();
        if (!verification.valid) return false;

        var it = verification.roots.iterator();
        while (it.next()) |entry| {
            if (!try chain_tracker.isValidRootForHeight(.{ .bytes = entry.value_ptr.bytes }, entry.key_ptr.*)) {
                return false;
            }
        }
        return true;
    }

    fn verifyValid(self: *const Beef, allocator: std.mem.Allocator, allow_txid_only: bool) !VerifyResult {
        var result = VerifyResult.init(self.allocator);
        errdefer result.deinit();

        var validation = try self.validateTransactions();
        defer validation.deinit();
        const keys = try collectKeys(self.allocator, &self.transactions);
        defer self.allocator.free(keys);

        if (validation.missing_inputs.len > 0 or
            validation.not_valid.len > 0 or
            validation.with_missing_inputs.len > 0 or
            (!allow_txid_only and validation.txid_only.len > 0))
        {
            return result;
        }

        for (self.bumps) |*bump| {
            if (bump.path.len == 0) continue;
            for (bump.path[0]) |leaf| {
                if (leaf.txid != true) continue;
                const txid = leaf.hash orelse return result;
                const root = try bump.computeRoot(allocator, txid);
                const height = bump.block_height;
                if (result.roots.get(height)) |existing| {
                    if (!existing.eql(.{ .bytes = root.bytes })) return result;
                } else {
                    try result.roots.put(height, .{ .bytes = root.bytes });
                }
            }
        }

        for (keys) |txid| {
            const beef_tx = self.transactions.get(txid) orelse continue;
            if (beef_tx.data_format == .RawTxAndBumpIndex) {
                const idx = beef_tx.bump_index orelse return result;
                if (idx >= self.bumps.len) return result;
                if (!txAppearsInBump(&self.bumps[idx], txid)) return result;
            }
        }

        result.valid = true;
        return result;
    }

    fn bytesV1(self: *const Beef) ![]u8 {
        var out = std.ArrayList(u8).initCapacity(self.allocator, 128) catch return error.OutOfMemory;
        defer out.deinit(self.allocator);

        try writeVersionAndBUMPs(self, &out);

        var buf: [9]u8 = undefined;
        const tx_len = try primitives.varint.VarInt.encodeInto(&buf, self.transactions.count());
        try out.appendSlice(self.allocator, buf[0..tx_len]);

        const keys = try collectKeys(self.allocator, &self.transactions);
        defer self.allocator.free(keys);

        for (keys) |txid| {
            const entry = self.transactions.get(txid) orelse continue;
            const tx = entry.transaction orelse continue;
            const tx_bytes = try tx.serialize(self.allocator);
            defer self.allocator.free(tx_bytes);
            try out.appendSlice(self.allocator, tx_bytes);
            if (entry.bump_index) |idx| {
                try out.append(self.allocator, 1);
                const idx_len = try primitives.varint.VarInt.encodeInto(&buf, idx);
                try out.appendSlice(self.allocator, buf[0..idx_len]);
            } else {
                try out.append(self.allocator, 0);
            }
        }

        return out.toOwnedSlice(self.allocator);
    }

    fn bytesV2(self: *const Beef) ![]u8 {
        var out = std.ArrayList(u8).initCapacity(self.allocator, 128) catch return error.OutOfMemory;
        defer out.deinit(self.allocator);

        try writeVersionAndBUMPs(self, &out);

        var buf: [9]u8 = undefined;
        const tx_len = try primitives.varint.VarInt.encodeInto(&buf, self.transactions.count());
        try out.appendSlice(self.allocator, buf[0..tx_len]);

        const keys = try collectKeys(self.allocator, &self.transactions);
        defer self.allocator.free(keys);

        for (keys) |txid| {
            const entry = self.transactions.get(txid) orelse continue;
            try out.append(self.allocator, @intFromEnum(entry.data_format));
            switch (entry.data_format) {
                .TxIDOnly => {
                    const known = entry.known_txid orelse txid;
                    try out.appendSlice(self.allocator, known.bytes[0..]);
                },
                .RawTx => {
                    const tx = entry.transaction orelse return error.InvalidEncoding;
                    const tx_bytes = try tx.serialize(self.allocator);
                    defer self.allocator.free(tx_bytes);
                    try out.appendSlice(self.allocator, tx_bytes);
                },
                .RawTxAndBumpIndex => {
                    const idx = entry.bump_index orelse return error.InvalidEncoding;
                    const idx_len = try primitives.varint.VarInt.encodeInto(&buf, idx);
                    try out.appendSlice(self.allocator, buf[0..idx_len]);
                    const tx = entry.transaction orelse return error.InvalidEncoding;
                    const tx_bytes = try tx.serialize(self.allocator);
                    defer self.allocator.free(tx_bytes);
                    try out.appendSlice(self.allocator, tx_bytes);
                },
            }
        }

        return out.toOwnedSlice(self.allocator);
    }
};

pub fn newBeefV1(allocator: std.mem.Allocator) Beef {
    return Beef.init(allocator, BEEF_V1);
}

pub fn newBeefV2(allocator: std.mem.Allocator) Beef {
    return Beef.init(allocator, BEEF_V2);
}

pub fn newBeefFromHex(allocator: std.mem.Allocator, hex_text: []const u8) !Beef {
    const bytes = try primitives.hex.decode(allocator, hex_text);
    defer allocator.free(bytes);
    return newBeefFromBytes(allocator, bytes);
}

pub fn newBeefFromBytes(allocator: std.mem.Allocator, bytes: []const u8) !Beef {
    if (bytes.len < 4) return error.InvalidEncoding;
    if (try readU32LE(bytes, 0) == ATOMIC_BEEF) {
        if (bytes.len < 36) return error.InvalidEncoding;
        return newBeefFromBytes(allocator, bytes[36..]);
    }

    var cursor: usize = 0;
    const version = try readVersion(bytes, &cursor);
    var beef = Beef.init(allocator, version);
    errdefer beef.deinit();

    beef.bumps = try readBUMPs(allocator, bytes, &cursor);
    switch (version) {
        BEEF_V1 => try readTransactionsV1(&beef, bytes, &cursor),
        BEEF_V2 => try readTransactionsV2(&beef, bytes, &cursor),
        else => return error.InvalidEncoding,
    }
    if (cursor != bytes.len) return error.InvalidEncoding;
    try hydrateInputs(&beef);
    return beef;
}

pub fn newTransactionFromBeef(allocator: std.mem.Allocator, bytes: []const u8) !txmod.Transaction {
    if (bytes.len < 4) return error.InvalidEncoding;
    const prefix = try readU32LE(bytes, 0);
    if (prefix == ATOMIC_BEEF) {
        if (bytes.len < 36) return error.InvalidEncoding;
        var txid_bytes: [32]u8 = undefined;
        @memcpy(&txid_bytes, bytes[4..36]);
        const txid = primitives.chainhash.Hash{ .bytes = txid_bytes };
        var beef = try newBeefFromBytes(allocator, bytes[36..]);
        defer beef.deinit();
        const tx = beef.findTransaction(txid) orelse return error.InvalidEncoding;
        return tx.clone(allocator);
    }

    const version = try readU32LE(bytes, 0);
    if (version != BEEF_V1) return error.InvalidEncoding;

    var cursor: usize = 0;
    _ = try readVersion(bytes, &cursor);
    const bumps = try readBUMPs(allocator, bytes, &cursor);
    defer {
        for (bumps) |*bump| bump.deinit(allocator);
        if (bumps.len > 0) allocator.free(bumps);
    }

    var last_tx: ?txmod.Transaction = null;
    errdefer if (last_tx) |tx| tx.deinit(allocator);

    const count = try readVarInt(bytes, &cursor);
    var i: usize = 0;
    while (i < count) : (i += 1) {
        var tx = try txmod.Transaction.parseFromCursor(allocator, bytes, &cursor);
        if (bytes.len < cursor + 1) return error.EndOfStream;

        const has_bump = bytes[cursor];
        cursor += 1;
        if (has_bump != 0) {
            const idx = try readVarInt(bytes, &cursor);
            if (idx >= bumps.len) return error.InvalidEncoding;
            tx.merkle_path = try bumps[idx].clone(allocator);
            tx.owns_merkle_path = true;
        }

        if (last_tx) |old_tx| old_tx.deinit(allocator);
        last_tx = tx;
    }
    if (cursor != bytes.len) {
        if (last_tx) |tx| tx.deinit(allocator);
        return error.InvalidEncoding;
    }

    return last_tx orelse error.InvalidEncoding;
}

pub fn newTransactionFromBeefHex(allocator: std.mem.Allocator, hex_text: []const u8) !txmod.Transaction {
    const bytes = try primitives.hex.decode(allocator, hex_text);
    defer allocator.free(bytes);
    return newTransactionFromBeef(allocator, bytes);
}

pub fn parseBeef(allocator: std.mem.Allocator, bytes: []const u8) !ParsedBeef {
    if (bytes.len < 4) return error.InvalidEncoding;
    const prefix = try readU32LE(bytes, 0);
    if (prefix == ATOMIC_BEEF) {
        if (bytes.len < 36) return error.InvalidEncoding;
        var txid_bytes: [32]u8 = undefined;
        @memcpy(&txid_bytes, bytes[4..36]);
        const txid = primitives.chainhash.Hash{ .bytes = txid_bytes };
        const beef = try newBeefFromBytes(allocator, bytes[36..]);
        const tx = beef.findTransaction(txid);
        return .{
            .beef = beef,
            .tx = if (tx) |transaction| try transaction.clone(allocator) else null,
            .txid = txid,
        };
    }

    if (prefix == BEEF_V1) {
        var tx = try newTransactionFromBeef(allocator, bytes);
        errdefer tx.deinit(allocator);
        const txid = try txidFor(allocator, &tx);
        return .{
            .beef = try newBeefFromBytes(allocator, bytes),
            .tx = tx,
            .txid = txid,
        };
    }

    return .{
        .beef = try newBeefFromBytes(allocator, bytes),
        .tx = null,
        .txid = null,
    };
}

pub fn atomicBeefFromTransaction(
    allocator: std.mem.Allocator,
    tx: *const txmod.Transaction,
) ![]u8 {
    var collected = std.AutoHashMap(primitives.chainhash.Hash, *const txmod.Transaction).init(allocator);
    defer collected.deinit();
    var ordered: std.ArrayList(primitives.chainhash.Hash) = .empty;
    defer ordered.deinit(allocator);
    var seen = std.AutoHashMap(primitives.chainhash.Hash, void).init(allocator);
    defer seen.deinit();

    var beef = Beef.init(allocator, BEEF_V2);
    defer beef.deinit();

    const txid = try txidFor(allocator, tx);
    try collectAncestors(allocator, tx, txid, &collected, &ordered, &seen, true);

    var bump_indices = std.AutoHashMap(u32, usize).init(allocator);
    defer bump_indices.deinit();
    var merged_bumps: std.ArrayList(MerklePath) = .empty;
    defer {
        for (merged_bumps.items) |*bump| bump.deinit(allocator);
        merged_bumps.deinit(allocator);
    }

    for (ordered.items) |ancestor_txid| {
        const ancestor = collected.get(ancestor_txid) orelse continue;
        const mp = ancestor.merkle_path orelse continue;
        if (bump_indices.get(mp.block_height)) |idx| {
            try merged_bumps.items[idx].combine(&mp, allocator);
        } else {
            try bump_indices.put(mp.block_height, merged_bumps.items.len);
            try merged_bumps.append(allocator, try mp.clone(allocator));
        }
    }

    beef.bumps = try merged_bumps.toOwnedSlice(allocator);

    for (ordered.items) |ancestor_txid| {
        const ancestor = collected.get(ancestor_txid) orelse continue;
        var cloned_tx = try ancestor.shallowClone(allocator);
        errdefer cloned_tx.deinit(allocator);

        var entry = BeefTx{
            .data_format = .RawTx,
            .transaction = cloned_tx,
        };

        if (ancestor.merkle_path) |mp| {
            const idx = bump_indices.get(mp.block_height) orelse return error.InvalidEncoding;
            cloned_tx.merkle_path = beef.bumps[idx];
            cloned_tx.owns_merkle_path = false;
            entry.data_format = .RawTxAndBumpIndex;
            entry.bump_index = idx;
            entry.transaction = cloned_tx;
        }

        const gop = try beef.transactions.getOrPut(ancestor_txid);
        if (gop.found_existing) return error.InvalidEncoding;
        gop.value_ptr.* = entry;
    }

    const beef_bytes = try beef.bytes();
    defer allocator.free(beef_bytes);

    var out = try allocator.alloc(u8, 4 + 32 + beef_bytes.len);
    std.mem.writeInt(u32, out[0..4], ATOMIC_BEEF, .little);
    @memcpy(out[4..36], txid.bytes[0..]);
    @memcpy(out[36..], beef_bytes);
    return out;
}

pub fn fromBeefInto(
    tx: *txmod.Transaction,
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !void {
    tx.* = try newTransactionFromBeef(allocator, bytes);
}

fn writeVersionAndBUMPs(self: *const Beef, out: *std.ArrayList(u8)) !void {
    var ver_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &ver_buf, self.version, .little);
    try out.appendSlice(self.allocator, &ver_buf);

    var buf: [9]u8 = undefined;
    const bump_len = try primitives.varint.VarInt.encodeInto(&buf, self.bumps.len);
    try out.appendSlice(self.allocator, buf[0..bump_len]);
    for (self.bumps) |*bump| {
        const bump_bytes = try bump.bytes(self.allocator);
        defer self.allocator.free(bump_bytes);
        try out.appendSlice(self.allocator, bump_bytes);
    }
}

fn readVersion(bytes: []const u8, cursor: *usize) !u32 {
    if (bytes.len < cursor.* + 4) return error.EndOfStream;
    const version = try readU32LEAt(bytes, cursor);
    if (version != BEEF_V1 and version != BEEF_V2) return error.InvalidEncoding;
    return version;
}

fn readBUMPs(allocator: std.mem.Allocator, bytes: []const u8, cursor: *usize) ![]MerklePath {
    const count = try readVarInt(bytes, cursor);
    const bumps = try allocator.alloc(MerklePath, count);
    errdefer allocator.free(bumps);
    for (0..count) |i| {
        bumps[i] = try MerklePath.parseFromCursor(allocator, bytes, cursor);
    }
    return bumps;
}

fn readTransactionsV1(beef: *Beef, bytes: []const u8, cursor: *usize) !void {
    const count = try readVarInt(bytes, cursor);
    for (0..count) |_| {
        var tx = try txmod.Transaction.parseFromCursor(beef.allocator, bytes, cursor);
        errdefer tx.deinit(beef.allocator);

        if (bytes.len < cursor.* + 1) return error.EndOfStream;
        const has_bump = bytes[cursor.*];
        cursor.* += 1;

        var bump_index: ?usize = null;
        if (has_bump != 0) {
            const idx = try readVarInt(bytes, cursor);
            if (idx >= beef.bumps.len) return error.InvalidEncoding;
            tx.merkle_path = beef.bumps[idx];
            tx.owns_merkle_path = false;
            bump_index = idx;
        }

        const txid = try txidFor(beef.allocator, &tx);
        const gop = try beef.transactions.getOrPut(txid);
        if (gop.found_existing) return error.InvalidEncoding;
        gop.value_ptr.* = .{
            .data_format = if (bump_index != null) .RawTxAndBumpIndex else .RawTx,
            .transaction = tx,
            .bump_index = bump_index,
        };
    }
}

fn readTransactionsV2(beef: *Beef, bytes: []const u8, cursor: *usize) !void {
    const count = try readVarInt(bytes, cursor);
    for (0..count) |_| {
        if (bytes.len < cursor.* + 1) return error.EndOfStream;
        const raw_format = bytes[cursor.*];
        const format: DataFormat = std.meta.intToEnum(DataFormat, raw_format) catch return error.InvalidEncoding;
        cursor.* += 1;

        switch (format) {
            .TxIDOnly => {
                if (bytes.len < cursor.* + 32) return error.EndOfStream;
                var txid_bytes: [32]u8 = undefined;
                @memcpy(&txid_bytes, bytes[cursor.* .. cursor.* + 32]);
                cursor.* += 32;
                const txid = primitives.chainhash.Hash{ .bytes = txid_bytes };
                const gop = try beef.transactions.getOrPut(txid);
                if (gop.found_existing) return error.InvalidEncoding;
                gop.value_ptr.* = .{
                    .data_format = .TxIDOnly,
                    .known_txid = txid,
                };
            },
            .RawTx => {
                const tx = try txmod.Transaction.parseFromCursor(beef.allocator, bytes, cursor);
                errdefer tx.deinit(beef.allocator);
                const txid = try txidFor(beef.allocator, &tx);
                const gop = try beef.transactions.getOrPut(txid);
                if (gop.found_existing) return error.InvalidEncoding;
                gop.value_ptr.* = .{
                    .data_format = .RawTx,
                    .transaction = tx,
                };
            },
            .RawTxAndBumpIndex => {
                const idx = try readVarInt(bytes, cursor);
                if (idx >= beef.bumps.len) return error.InvalidEncoding;

                var tx = try txmod.Transaction.parseFromCursor(beef.allocator, bytes, cursor);
                errdefer tx.deinit(beef.allocator);
                tx.merkle_path = beef.bumps[idx];
                tx.owns_merkle_path = false;
                const txid = try txidFor(beef.allocator, &tx);
                const gop = try beef.transactions.getOrPut(txid);
                if (gop.found_existing) return error.InvalidEncoding;
                gop.value_ptr.* = .{
                    .data_format = .RawTxAndBumpIndex,
                    .transaction = tx,
                    .bump_index = idx,
                };
            },
        }
    }
}

fn hydrateInputs(beef: *Beef) !void {
    var it = beef.transactions.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.transaction) |*tx| {
            const inputs = @constCast(tx.inputs);
            for (inputs) |*input| {
                input.source_transaction = null;
                const source_txid = primitives.chainhash.Hash{ .bytes = input.previous_outpoint.txid.bytes };
                if (beef.transactions.getPtr(source_txid)) |source_entry| {
                    if (source_entry.transaction) |*source_tx| {
                        input.source_transaction = @ptrCast(source_tx);
                        if (input.previous_outpoint.index < source_tx.outputs.len) {
                            if (input.source_output) |*source_output| source_output.deinit(beef.allocator);
                            input.source_output = try source_tx.outputs[input.previous_outpoint.index].clone(beef.allocator);
                        }
                    }
                }
            }
        }
    }
}

fn collectAncestors(
    allocator: std.mem.Allocator,
    tx: *const txmod.Transaction,
    txid: primitives.chainhash.Hash,
    collected: *std.AutoHashMap(primitives.chainhash.Hash, *const txmod.Transaction),
    ordered: *std.ArrayList(primitives.chainhash.Hash),
    seen: *std.AutoHashMap(primitives.chainhash.Hash, void),
    allow_partial: bool,
) !void {
    if (seen.contains(txid)) return;
    try seen.put(txid, {});
    try collected.put(txid, tx);

    if (tx.merkle_path == null) {
        for (tx.inputs) |input| {
            const source_tx = txmod.sourceTransactionForInput(&input) orelse {
                if (allow_partial) continue;
                return error.MissingSourceTransaction;
            };
            const source_txid = primitives.chainhash.Hash{ .bytes = input.previous_outpoint.txid.bytes };
            try collectAncestors(allocator, source_tx, source_txid, collected, ordered, seen, allow_partial);
        }
    }

    try ordered.append(allocator, txid);
}

fn readVarInt(bytes: []const u8, cursor: *usize) !usize {
    const vi = try primitives.varint.VarInt.parse(bytes[cursor.*..]);
    cursor.* += vi.len;
    return std.math.cast(usize, vi.value) orelse return error.Overflow;
}

fn txidFor(allocator: std.mem.Allocator, tx: *const txmod.Transaction) !primitives.chainhash.Hash {
    const raw = try tx.serialize(allocator);
    defer allocator.free(raw);
    return primitives.chainhash.doubleHashH(raw);
}

fn collectKeys(
    allocator: std.mem.Allocator,
    map: *const std.AutoHashMap(primitives.chainhash.Hash, BeefTx),
) ![]primitives.chainhash.Hash {
    const keys = try allocator.alloc(primitives.chainhash.Hash, map.count());
    var i: usize = 0;
    var it = map.iterator();
    while (it.next()) |entry| : (i += 1) {
        keys[i] = entry.key_ptr.*;
    }
    std.sort.insertion(primitives.chainhash.Hash, keys, {}, struct {
        fn lessThan(_: void, a: primitives.chainhash.Hash, b: primitives.chainhash.Hash) bool {
            return std.mem.lessThan(u8, &a.bytes, &b.bytes);
        }
    }.lessThan);
    return keys;
}

fn collectHashKeys(
    allocator: std.mem.Allocator,
    map: *const std.AutoHashMap(primitives.chainhash.Hash, void),
) ![]primitives.chainhash.Hash {
    const keys = try allocator.alloc(primitives.chainhash.Hash, map.count());
    var i: usize = 0;
    var it = map.iterator();
    while (it.next()) |entry| : (i += 1) {
        keys[i] = entry.key_ptr.*;
    }
    sortHashes(keys);
    return keys;
}

fn sortHashes(hashes: []primitives.chainhash.Hash) void {
    std.sort.insertion(primitives.chainhash.Hash, hashes, {}, struct {
        fn lessThan(_: void, a: primitives.chainhash.Hash, b: primitives.chainhash.Hash) bool {
            return std.mem.lessThan(u8, &a.bytes, &b.bytes);
        }
    }.lessThan);
}

fn txAppearsInBump(bump: *const MerklePath, txid: primitives.chainhash.Hash) bool {
    if (bump.path.len == 0) return false;
    for (bump.path[0]) |leaf| {
        const hash = leaf.hash orelse continue;
        if (leaf.txid == true and std.mem.eql(u8, &hash.bytes, &txid.bytes)) return true;
    }
    return false;
}

fn readU32LE(bytes: []const u8, offset: usize) !u32 {
    if (bytes.len < offset + 4) return error.EndOfStream;
    const ptr = @as(*const [4]u8, @ptrCast(bytes[offset .. offset + 4].ptr));
    return std.mem.readInt(u32, ptr, .little);
}

fn readU32LEAt(bytes: []const u8, cursor: *usize) !u32 {
    const val = try readU32LE(bytes, cursor.*);
    cursor.* += 4;
    return val;
}

test "atomic BEEF clones root transaction safely" {
    const allocator = std.testing.allocator;

    var tx = txmod.Transaction{
        .version = 1,
        .inputs = try allocator.alloc(Input, 1),
        .outputs = try allocator.alloc(Output, 1),
        .lock_time = 0,
    };
    defer tx.deinit(allocator);

    @constCast(tx.inputs)[0] = .{
        .previous_outpoint = .{
            .txid = .{ .bytes = [_]u8{0x11} ** 32 },
            .index = 0,
        },
        .unlocking_script = .{ .bytes = &[_]u8{0x51} },
        .sequence = 0xffff_ffff,
        .source_output = .{
            .satoshis = 10,
            .locking_script = .{ .bytes = &[_]u8{0x51} },
        },
    };
    @constCast(tx.outputs)[0] = .{
        .satoshis = 5,
        .locking_script = .{ .bytes = &[_]u8{0x51} },
    };

    const atomic = try atomicBeefFromTransaction(allocator, &tx);
    defer allocator.free(atomic);

    const serialized = try tx.serialize(allocator);
    defer allocator.free(serialized);
    const serialized_again = try tx.serialize(allocator);
    defer allocator.free(serialized_again);

    try std.testing.expectEqualSlices(u8, &[_]u8{0x51}, tx.inputs[0].unlocking_script.bytes);
    try std.testing.expectEqualSlices(u8, serialized, serialized_again);
}

test "BEEF v2 hydrates source outputs regardless of transaction order" {
    const allocator = std.testing.allocator;

    var parent = txmod.Transaction{
        .version = 1,
        .inputs = try allocator.alloc(Input, 0),
        .outputs = try allocator.alloc(Output, 1),
        .lock_time = 0,
    };
    defer parent.deinit(allocator);
    @constCast(parent.outputs)[0] = .{
        .satoshis = 42,
        .locking_script = .{ .bytes = &[_]u8{ 0x51, 0xac } },
    };

    const parent_txid = try txidFor(allocator, &parent);
    var child = txmod.Transaction{
        .version = 1,
        .inputs = try allocator.alloc(Input, 1),
        .outputs = try allocator.alloc(Output, 1),
        .lock_time = 0,
    };
    defer child.deinit(allocator);
    @constCast(child.inputs)[0] = .{
        .previous_outpoint = .{
            .txid = .{ .bytes = parent_txid.bytes },
            .index = 0,
        },
        .unlocking_script = .{ .bytes = &[_]u8{0x51} },
        .sequence = 0xffff_ffff,
    };
    @constCast(child.outputs)[0] = .{
        .satoshis = 1,
        .locking_script = .{ .bytes = &[_]u8{0x51} },
    };

    const parent_bytes = try parent.serialize(allocator);
    defer allocator.free(parent_bytes);
    const child_bytes = try child.serialize(allocator);
    defer allocator.free(child_bytes);

    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    var buf4: [4]u8 = undefined;

    std.mem.writeInt(u32, &buf4, BEEF_V2, .little);
    try bytes.appendSlice(allocator, &buf4);
    try bytes.append(allocator, 0); // no BUMPs
    try bytes.append(allocator, 2); // two transactions
    try bytes.append(allocator, @intFromEnum(DataFormat.RawTx));
    try bytes.appendSlice(allocator, child_bytes);
    try bytes.append(allocator, @intFromEnum(DataFormat.RawTx));
    try bytes.appendSlice(allocator, parent_bytes);

    var beef = try newBeefFromBytes(allocator, bytes.items);
    defer beef.deinit();

    const child_entry = beef.findTransaction(try txidFor(allocator, &child)) orelse return error.TestUnexpectedResult;
    try std.testing.expect(child_entry.inputs[0].source_output != null);
    try std.testing.expect(txmod.sourceTransactionForInput(&child_entry.inputs[0]) != null);
    const source_output = child_entry.inputs[0].source_output.?;
    try std.testing.expectEqual(@as(i64, 42), source_output.satoshis);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x51, 0xac }, source_output.locking_script.bytes);
    try std.testing.expectEqual(parent_txid, try txidFor(allocator, txmod.sourceTransactionForInput(&child_entry.inputs[0]).?));
}

test "newTransactionFromBeefHex round trips atomic beef hex" {
    const allocator = std.testing.allocator;

    var tx = txmod.Transaction{
        .version = 1,
        .inputs = try allocator.alloc(Input, 0),
        .outputs = try allocator.alloc(Output, 1),
        .lock_time = 0,
    };
    defer tx.deinit(allocator);
    @constCast(tx.outputs)[0] = .{
        .satoshis = 21,
        .locking_script = .{ .bytes = &[_]u8{0x51} },
    };

    const atomic = try atomicBeefFromTransaction(allocator, &tx);
    defer allocator.free(atomic);

    const atomic_hex = try allocator.alloc(u8, atomic.len * 2);
    defer allocator.free(atomic_hex);
    _ = try primitives.hex.encodeLower(atomic, atomic_hex);

    var parsed = try newTransactionFromBeefHex(allocator, atomic_hex);
    defer parsed.deinit(allocator);

    try std.testing.expectEqual(try txidFor(allocator, &tx), try txidFor(allocator, &parsed));
}

test "BEEF validateTransactions resolves proven ancestor chains" {
    const allocator = std.testing.allocator;

    var parent = txmod.Transaction{
        .version = 1,
        .inputs = try allocator.alloc(Input, 0),
        .outputs = try allocator.alloc(Output, 1),
        .lock_time = 0,
    };
    defer parent.deinit(allocator);
    @constCast(parent.outputs)[0] = .{
        .satoshis = 50,
        .locking_script = .{ .bytes = &[_]u8{ 0x51, 0xac } },
    };

    const parent_txid = try txidFor(allocator, &parent);

    var child = txmod.Transaction{
        .version = 1,
        .inputs = try allocator.alloc(Input, 1),
        .outputs = try allocator.alloc(Output, 1),
        .lock_time = 0,
    };
    defer child.deinit(allocator);
    @constCast(child.inputs)[0] = .{
        .previous_outpoint = .{
            .txid = .{ .bytes = parent_txid.bytes },
            .index = 0,
        },
        .unlocking_script = .{ .bytes = &[_]u8{0x51} },
        .sequence = 0xffff_ffff,
    };
    @constCast(child.outputs)[0] = .{
        .satoshis = 25,
        .locking_script = .{ .bytes = &[_]u8{0x51} },
    };

    var beef = newBeefV2(allocator);
    defer beef.deinit();
    beef.bumps = try allocator.alloc(MerklePath, 1);
    beef.bumps[0] = .{
        .block_height = 101,
        .path = try allocator.alloc([]@import("../spv/merkle_path.zig").PathElement, 1),
    };
    beef.bumps[0].path[0] = try allocator.alloc(@import("../spv/merkle_path.zig").PathElement, 1);
    beef.bumps[0].path[0][0] = .{
        .offset = 0,
        .hash = .{ .bytes = parent_txid.bytes },
        .txid = true,
    };

    var parent_entry = try parent.clone(allocator);
    parent_entry.merkle_path = beef.bumps[0];
    parent_entry.owns_merkle_path = false;
    try beef.transactions.put(parent_txid, .{
        .data_format = .RawTxAndBumpIndex,
        .transaction = parent_entry,
        .bump_index = 0,
    });

    const child_txid = try txidFor(allocator, &child);
    try beef.transactions.put(child_txid, .{
        .data_format = .RawTx,
        .transaction = try child.clone(allocator),
    });

    try hydrateInputs(&beef);

    var validation = try beef.validateTransactions();
    defer validation.deinit();

    try std.testing.expect(containsHash(validation.valid, parent_txid));
    try std.testing.expect(containsHash(validation.valid, child_txid));
    try std.testing.expectEqual(@as(usize, 0), validation.not_valid.len);
    try std.testing.expectEqual(@as(usize, 0), validation.missing_inputs.len);
}

test "BEEF clone preserves hydrated ancestry after original deinit" {
    const allocator = std.testing.allocator;

    var parent = txmod.Transaction{
        .version = 1,
        .inputs = try allocator.alloc(Input, 0),
        .outputs = try allocator.alloc(Output, 1),
        .lock_time = 0,
    };
    defer parent.deinit(allocator);
    @constCast(parent.outputs)[0] = .{
        .satoshis = 33,
        .locking_script = .{ .bytes = &[_]u8{ 0x51, 0xac } },
    };
    const parent_txid = try txidFor(allocator, &parent);

    var child = txmod.Transaction{
        .version = 1,
        .inputs = try allocator.alloc(Input, 1),
        .outputs = try allocator.alloc(Output, 1),
        .lock_time = 0,
    };
    defer child.deinit(allocator);
    @constCast(child.inputs)[0] = .{
        .previous_outpoint = .{
            .txid = .{ .bytes = parent_txid.bytes },
            .index = 0,
        },
        .unlocking_script = .{ .bytes = &[_]u8{0x51} },
        .sequence = 0xffff_ffff,
    };
    @constCast(child.outputs)[0] = .{
        .satoshis = 5,
        .locking_script = .{ .bytes = &[_]u8{0x51} },
    };

    const parent_bytes = try parent.serialize(allocator);
    defer allocator.free(parent_bytes);
    const child_bytes = try child.serialize(allocator);
    defer allocator.free(child_bytes);

    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    var buf4: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf4, BEEF_V2, .little);
    try bytes.appendSlice(allocator, &buf4);
    try bytes.append(allocator, 0);
    try bytes.append(allocator, 2);
    try bytes.append(allocator, @intFromEnum(DataFormat.RawTx));
    try bytes.appendSlice(allocator, child_bytes);
    try bytes.append(allocator, @intFromEnum(DataFormat.RawTx));
    try bytes.appendSlice(allocator, parent_bytes);

    var beef = try newBeefFromBytes(allocator, bytes.items);
    var cloned = try beef.clone(allocator);
    beef.deinit();
    defer cloned.deinit();

    const cloned_child = cloned.findTransaction(try txidFor(allocator, &child)) orelse return error.TestUnexpectedResult;
    try std.testing.expect(txmod.sourceTransactionForInput(&cloned_child.inputs[0]) != null);
    try std.testing.expectEqual(@as(i64, 33), txmod.sourceOutputForInput(&cloned_child.inputs[0]).?.satoshis);

    const serialized = try cloned_child.serialize(allocator);
    defer allocator.free(serialized);
    try std.testing.expect(serialized.len > 0);
}

test "BEEF verify checks chain tracker roots" {
    const allocator = std.testing.allocator;

    var tx = txmod.Transaction{
        .version = 1,
        .inputs = try allocator.alloc(Input, 0),
        .outputs = try allocator.alloc(Output, 1),
        .lock_time = 0,
    };
    defer tx.deinit(allocator);
    @constCast(tx.outputs)[0] = .{
        .satoshis = 10,
        .locking_script = .{ .bytes = &[_]u8{0x51} },
    };

    const txid = try txidFor(allocator, &tx);

    var beef = newBeefV2(allocator);
    defer beef.deinit();
    beef.bumps = try allocator.alloc(MerklePath, 1);
    beef.bumps[0] = .{
        .block_height = 7,
        .path = try allocator.alloc([]@import("../spv/merkle_path.zig").PathElement, 1),
    };
    beef.bumps[0].path[0] = try allocator.alloc(@import("../spv/merkle_path.zig").PathElement, 1);
    beef.bumps[0].path[0][0] = .{
        .offset = 0,
        .hash = .{ .bytes = txid.bytes },
        .txid = true,
    };

    var entry = try tx.clone(allocator);
    entry.merkle_path = beef.bumps[0];
    entry.owns_merkle_path = false;
    try beef.transactions.put(txid, .{
        .data_format = .RawTxAndBumpIndex,
        .transaction = entry,
        .bump_index = 0,
    });

    const Tracker = struct {
        expected_root: primitives.chainhash.Hash,
        expected_height: u32,

        pub fn isValidRootForHeight(self: @This(), root: @import("../crypto/lib.zig").Hash256, height: u32) !bool {
            return std.mem.eql(u8, &root.bytes, &self.expected_root.bytes) and height == self.expected_height;
        }
    };

    try std.testing.expect(try beef.isValid(allocator, false));
    try std.testing.expect(try beef.verify(allocator, Tracker{
        .expected_root = txid,
        .expected_height = 7,
    }, false));
    try std.testing.expect(!(try beef.verify(allocator, Tracker{
        .expected_root = .{ .bytes = [_]u8{0xaa} ** 32 },
        .expected_height = 7,
    }, false)));
}

test "BEEF txid-only entries require proof unless explicitly allowed" {
    const allocator = std.testing.allocator;
    const txid = primitives.chainhash.Hash{ .bytes = [_]u8{0x77} ** 32 };

    var beef = newBeefV2(allocator);
    defer beef.deinit();
    beef.bumps = try allocator.alloc(MerklePath, 1);
    beef.bumps[0] = .{
        .block_height = 33,
        .path = try allocator.alloc([]@import("../spv/merkle_path.zig").PathElement, 1),
    };
    beef.bumps[0].path[0] = try allocator.alloc(@import("../spv/merkle_path.zig").PathElement, 1);
    beef.bumps[0].path[0][0] = .{
        .offset = 0,
        .hash = .{ .bytes = txid.bytes },
        .txid = true,
    };
    try beef.transactions.put(txid, .{
        .data_format = .TxIDOnly,
        .known_txid = txid,
    });

    var validation = try beef.validateTransactions();
    defer validation.deinit();

    try std.testing.expect(containsHash(validation.txid_only, txid));
    try std.testing.expect(containsHash(validation.valid, txid));
    try std.testing.expect(!(try beef.isValid(allocator, false)));
    try std.testing.expect(try beef.isValid(allocator, true));
}

test "atomicBeefFromTransaction includes ancestor transactions" {
    const allocator = std.testing.allocator;

    var grandparent = txmod.Transaction{
        .version = 1,
        .inputs = try allocator.alloc(Input, 0),
        .outputs = try allocator.alloc(Output, 1),
        .lock_time = 0,
    };
    defer grandparent.deinit(allocator);
    @constCast(grandparent.outputs)[0] = .{
        .satoshis = 100,
        .locking_script = .{ .bytes = &[_]u8{0x51} },
    };
    const grandparent_txid = try txidFor(allocator, &grandparent);
    grandparent.merkle_path = .{
        .block_height = 88,
        .path = try allocator.alloc([]@import("../spv/merkle_path.zig").PathElement, 1),
    };
    grandparent.owns_merkle_path = true;
    grandparent.merkle_path.?.path[0] = try allocator.alloc(@import("../spv/merkle_path.zig").PathElement, 1);
    grandparent.merkle_path.?.path[0][0] = .{
        .offset = 0,
        .hash = .{ .bytes = grandparent_txid.bytes },
        .txid = true,
    };

    var parent = txmod.Transaction{
        .version = 1,
        .inputs = try allocator.alloc(Input, 1),
        .outputs = try allocator.alloc(Output, 1),
        .lock_time = 0,
    };
    defer parent.deinit(allocator);
    @constCast(parent.inputs)[0] = .{
        .previous_outpoint = .{
            .txid = .{ .bytes = grandparent_txid.bytes },
            .index = 0,
        },
        .unlocking_script = .{ .bytes = &[_]u8{0x51} },
        .sequence = 0xffff_ffff,
        .source_output = try grandparent.outputs[0].clone(allocator),
        .source_transaction = @ptrCast(&grandparent),
    };
    @constCast(parent.outputs)[0] = .{
        .satoshis = 70,
        .locking_script = .{ .bytes = &[_]u8{0x51} },
    };
    const parent_txid = try txidFor(allocator, &parent);

    var child = txmod.Transaction{
        .version = 1,
        .inputs = try allocator.alloc(Input, 1),
        .outputs = try allocator.alloc(Output, 1),
        .lock_time = 0,
    };
    defer child.deinit(allocator);
    @constCast(child.inputs)[0] = .{
        .previous_outpoint = .{
            .txid = .{ .bytes = parent_txid.bytes },
            .index = 0,
        },
        .unlocking_script = .{ .bytes = &[_]u8{0x51} },
        .sequence = 0xffff_ffff,
        .source_output = try parent.outputs[0].clone(allocator),
        .source_transaction = @ptrCast(&parent),
    };
    @constCast(child.outputs)[0] = .{
        .satoshis = 50,
        .locking_script = .{ .bytes = &[_]u8{0x51} },
    };
    const child_txid = try txidFor(allocator, &child);

    const atomic = try atomicBeefFromTransaction(allocator, &child);
    defer allocator.free(atomic);

    var parsed = try parseBeef(allocator, atomic);
    defer parsed.deinit();

    try std.testing.expectEqual(child_txid, parsed.txid.?);
    try std.testing.expect(parsed.beef.findTransaction(grandparent_txid) != null);
    try std.testing.expect(parsed.beef.findTransaction(parent_txid) != null);
    try std.testing.expect(parsed.beef.findTransaction(child_txid) != null);

    const parsed_child = parsed.beef.findTransaction(child_txid) orelse return error.TestUnexpectedResult;
    try std.testing.expect(txmod.sourceTransactionForInput(&parsed_child.inputs[0]) != null);
    try std.testing.expectEqual(@as(i64, 70), txmod.sourceOutputForInput(&parsed_child.inputs[0]).?.satoshis);
    const parsed_parent = txmod.sourceTransactionForInput(&parsed_child.inputs[0]).?;
    try std.testing.expect(txmod.sourceTransactionForInput(&parsed_parent.inputs[0]) != null);
    try std.testing.expectEqual(@as(i64, 100), txmod.sourceOutputForInput(&parsed_parent.inputs[0]).?.satoshis);
}

test "parseBeef returns the last transaction for legacy BEEF v1" {
    const allocator = std.testing.allocator;

    var parent = txmod.Transaction{
        .version = 1,
        .inputs = try allocator.alloc(Input, 0),
        .outputs = try allocator.alloc(Output, 1),
        .lock_time = 0,
    };
    defer parent.deinit(allocator);
    @constCast(parent.outputs)[0] = .{
        .satoshis = 50,
        .locking_script = .{ .bytes = &[_]u8{0x51} },
    };
    const parent_txid = try txidFor(allocator, &parent);

    var child = txmod.Transaction{
        .version = 1,
        .inputs = try allocator.alloc(Input, 1),
        .outputs = try allocator.alloc(Output, 1),
        .lock_time = 0,
    };
    defer child.deinit(allocator);
    @constCast(child.inputs)[0] = .{
        .previous_outpoint = .{
            .txid = .{ .bytes = parent_txid.bytes },
            .index = 0,
        },
        .unlocking_script = .{ .bytes = &[_]u8{0x51} },
        .sequence = 0xffff_ffff,
    };
    @constCast(child.outputs)[0] = .{
        .satoshis = 25,
        .locking_script = .{ .bytes = &[_]u8{0x51} },
    };
    const child_txid = try txidFor(allocator, &child);

    const parent_bytes = try parent.serialize(allocator);
    defer allocator.free(parent_bytes);
    const child_bytes = try child.serialize(allocator);
    defer allocator.free(child_bytes);

    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    var buf4: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf4, BEEF_V1, .little);
    try bytes.appendSlice(allocator, &buf4);
    try bytes.append(allocator, 0); // no bumps
    try bytes.append(allocator, 2); // two transactions
    try bytes.appendSlice(allocator, parent_bytes);
    try bytes.append(allocator, 0); // no bump
    try bytes.appendSlice(allocator, child_bytes);
    try bytes.append(allocator, 0); // no bump

    var parsed = try parseBeef(allocator, bytes.items);
    defer parsed.deinit();

    try std.testing.expect(parsed.tx != null);
    try std.testing.expectEqual(child_txid, parsed.txid.?);
    const parsed_tx = parsed.tx.?;
    try std.testing.expectEqual(child_txid, try txidFor(allocator, &parsed_tx));
    try std.testing.expect(parsed.beef.findTransaction(child_txid) != null);
}

test "newBeefFromBytes rejects duplicate transaction entries" {
    const allocator = std.testing.allocator;

    var tx = txmod.Transaction{
        .version = 1,
        .inputs = try allocator.alloc(Input, 0),
        .outputs = try allocator.alloc(Output, 1),
        .lock_time = 0,
    };
    defer tx.deinit(allocator);
    @constCast(tx.outputs)[0] = .{
        .satoshis = 10,
        .locking_script = .{ .bytes = &[_]u8{0x51} },
    };

    const tx_bytes = try tx.serialize(allocator);
    defer allocator.free(tx_bytes);

    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    var buf4: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf4, BEEF_V2, .little);
    try bytes.appendSlice(allocator, &buf4);
    try bytes.append(allocator, 0); // no bumps
    try bytes.append(allocator, 2); // two transactions
    try bytes.append(allocator, @intFromEnum(DataFormat.RawTx));
    try bytes.appendSlice(allocator, tx_bytes);
    try bytes.append(allocator, @intFromEnum(DataFormat.RawTx));
    try bytes.appendSlice(allocator, tx_bytes);

    try std.testing.expectError(error.InvalidEncoding, newBeefFromBytes(allocator, bytes.items));
}

test "newBeefFromBytes rejects trailing bytes" {
    const allocator = std.testing.allocator;

    var tx = txmod.Transaction{
        .version = 1,
        .inputs = try allocator.alloc(Input, 0),
        .outputs = try allocator.alloc(Output, 1),
        .lock_time = 0,
    };
    defer tx.deinit(allocator);
    @constCast(tx.outputs)[0] = .{
        .satoshis = 7,
        .locking_script = .{ .bytes = &[_]u8{0x51} },
    };

    const tx_bytes = try tx.serialize(allocator);
    defer allocator.free(tx_bytes);

    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    var buf4: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf4, BEEF_V2, .little);
    try bytes.appendSlice(allocator, &buf4);
    try bytes.append(allocator, 0); // no bumps
    try bytes.append(allocator, 1); // one transaction
    try bytes.append(allocator, @intFromEnum(DataFormat.RawTx));
    try bytes.appendSlice(allocator, tx_bytes);
    try bytes.append(allocator, 0xaa); // trailing garbage

    try std.testing.expectError(error.InvalidEncoding, newBeefFromBytes(allocator, bytes.items));
}

fn containsHash(hashes: []const primitives.chainhash.Hash, needle: primitives.chainhash.Hash) bool {
    for (hashes) |hash| {
        if (hash.eql(needle)) return true;
    }
    return false;
}
