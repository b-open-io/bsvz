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

const go_brc62_hex =
    "0100beef01fe636d0c0007021400fe507c0c7aa754cef1f7889d5fd395cf1f785dd7de98eed895dbedfe4e5bc70d1502ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e010b00bc4ff395efd11719b277694cface5aa50d085a0bb81f613f70313acd28cf4557010400574b2d9142b8d28b61d88e3b2c3f44d858411356b49a28a4643b6d1a6a092a5201030051a05fc84d531b5d250c23f4f886f6812f9fe3f402d61607f977b4ecd2701c19010000fd781529d58fc2523cf396a7f25440b409857e7e221766c57214b1d38c7b481f01010062f542f45ea3660f86c013ced80534cb5fd4c19d66c56e7e8c5d4bf2d40acc5e010100b121e91836fd7cd5102b654e9f72f3cf6fdbfd0b161c53a9c54b12c841126331020100000001cd4e4cac3c7b56920d1e7655e7e260d31f29d9a388d04910f1bbd72304a79029010000006b483045022100e75279a205a547c445719420aa3138bf14743e3f42618e5f86a19bde14bb95f7022064777d34776b05d816daf1699493fcdf2ef5a5ab1ad710d9c97bfb5b8f7cef3641210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013e660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000001000100000001ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e000000006a47304402203a61a2e931612b4bda08d541cfb980885173b8dcf64a3471238ae7abcd368d6402204cbf24f04b9aa2256d8901f0ed97866603d2be8324c2bfb7a37bf8fc90edd5b441210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013c660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000000";
const go_beef_set =
    "0200beef03fef1550d001102fd20c2009591fd79f7fb1fbd24c2fdc4911da930e1d7386f0216b6446b85eea29f978f1bfd21c202ac2a05abdae46fc2555c36a76035dedbf9fac4fc349eabffbd9d62ba440ffcb101fd116100cabeb714ea9a3f15a5e4f6138f6dd6b75bab32d8b40d178a0514e6e1e1b372f701fd8930007e04df7216a1d29bb8caabd1f78014b1b4f336eb6aee76bcf1797456ddc86b7501fd451800796afe5b113d8933f5eef2d180e72dc4b644fd76fb1243dfb791d9863702573701fd230c007a6edc003e02c429391cbf426816885731cb8054410599884eed508917a2f57c01fd100600eaa540de74506ed6abcb48e38cc544c53d373269271a7e6cf2143b7cc85d7ea401fd0903001e31aa04628b99d6cfa3e21fb4a7e773487ebc86a504e511eaff3f2176267b9401fd85010031e0d053497f85228b02879f69c4c7b43fb5abc3e0e47ea49a63853b117c9b5001c30083339d5a5b97ad77b74d3538678bb20ea7e61f8b02c24a625933eb496bebd3480160008ee445baec1613d591344a9915d77652f508e6442cd394626a3ff308bcb151f1013100f3f68f2a72e47bb41377e9e429daa496cd220bdcf702a36a209f9feba58d5552011900a01c52f4099bc7bdfea772ab03739bf009d72f24f68b5c4f8cc71a8c4da80804010d00c2ce2d5bfb9cbab9983ae1c871974f23a32c585d9b8440acc4ef5203c1d6c05401070072c7fc59a1717e90633f10d322e0f63272ae97c017d1efae04e4090abeeafac3010200a7aa5fa5576d1de6dd0e32d769592bc247be7bbd0b3e36e2d579fa1ec7d6ebce010000090cba670bea2e0d5c36e979e4cf9f79ad0874d734fb782fec2496d4c554e321010100d963646680643df73c34d7fa16f173595cf32a9ed6f64d2c8ee88a8af6b7bf52fedf590d001202fe66130200023275c6dde10d32d61af52b412b1e3956b5cd085605cd521778f11d53849fdb0cfe6713020000cd5e2298cf4d809c698c8adeeab66718e6b75b3d528bce74e6e01b984c736df901feb209010000736013454e087c89d813c99a043c9029cf2d427815c6a98ba3641c384ae52c4701fdd884007f742824bddca1582e4ded866d9609d9473397f8b86625376be74684f7fb947f01fd6d4200eb7f54ce4f920a3e4c7f96ef6b2d199c519df1b1286415581187ca608f3e47b801fd372100fa6c1c8cba3d3d5d030cd98eb91498cdffe70f0dad1000e123157d5dac22e22a01fd9a1000104c0294e478fbcac4e2325403afd86370c86043f295978b809004b2687a6c9a01fd4c08009ef5a5eaf16cab45a239c43852296ab323ca21faf256ab9768dd0a2f39970ec201fd2704006161cbd1755b66815eb69613b574920e9e836c8c3772aa2260ad3639848d520b01fd1202005e04b5afc0ea8d29dc22b611536832a2a2e7c860bbf4227ce0bdcc8a0e66284601fd0801009719f5f90e3937f3921045d202522fe315da1331acc3cce472c4b084d0debe65018500d79a1c3d45a3c41bf6526a9adbac2676159d2f3c753d7d3b6dba1dc3cbdd3c520143006b88b582d985bffc511556e471a6a20cfda2d41837245329f714214e009a3e48012000c1840dbdfc3014f1e912882b971c030fd21c0b023c01fe6fd7470d6d9bb2ab86011100f9c3de08d38588e225a5ee5334a3c03771a0b51318ca388dd1b5826951604d750109006e2b2e926c86214620d306a59522eee438a79157e9360cb76ee14a868fccc482010500d5c43ea372c432861db73ba0a6897fa29855e542a6ed910626dfb8954d94fa47010300d7863bafb5ca841ca0b13736fced1d492f0f741cb0a2beab1cafa517c878ae2c010000174ccda0879c20b85fa26d423deb0b34c5f2787127e244ccacfae39b5ba8fea7feeb590d001602fe46b3060002fa6ae8371111956f74412e3b1effcbd4fcb278124b6365b34c8cc20a5287bafffe47b306000011883eed76bdc7e7fb79efe23e3c50aa825ade46d79895de1a246e3d69a5b8cf01fea2590300009c92d7f67ac06e4bce0de4f18f438056f25138ee1a0cf61ed3a6d7f32261339b01fed0ac01000006178026214d61dc19c91cb5c08481f2f3daf03392c359de424cbd5d7135c5cf01fd69d6000174f6863438909d648fea32cdd65cbf457ab717f9be327d5d4352dbf157671e01fd356b0059536ea55010906b7071e36f78b20faaaede46a7f27ba4916dc1655836c73de701fd9b3500dee845c02c827dbcd862de359f5e6ad0ecca59213d9eb01896374d9efb7af9fd01fdcc1a00b22861b84b4537dfdaa8eb51957a51007af7836677ad14074601de6cd6c2871c01fd670d00591e76e7b07b26a6d7e940ec4f84497d9f3c7be111b15c336b24d83227db0c1001fdb20600f142d0ff9b2ddb7c21d8913f02adc7abc51fcdd5253154339450b87b59859aa601fd580300ce0307ff2027d405b8afa8a5c8834e9cc8bd073c4f463c3657562bbdb7843fe601fdad010027a3ce3a9829a3df0d9074099a6a3d76c81600a6a9c50f6cf857fb823c1a783901d700cca7689680c528f0a93fd9c980577016b37ce67ce75b1d728c4fa23008b1652b016a00b74bd3ab6c94f1216a803849afc254f37eea378c89167ff0686223db82767e3a013400434d5f48f733bb69fc5f0bd8238ffaec8d002951e6a1b52484fcc05819078372011b0053fef8153f4aed8aa8bdebeae0a6c1aa7712b84887fb565bcd9232fdd60fb0c0010c00009d9f21a9bc9e9d8c99aac9a1df47ffe02334fcb8bc8f3797d64c2564b3bf44010700838a284a4ee33c455b303e1eb23428b35d264b35c4f4b42bd6c68f1a7279f38801020042820e1ab5dbb77b0a6f266167b453f672d007d0c6eddc6229ce57c941f46c670100002c0da37e0453e7d01c810d2280a84792086b1fe1bc232e76ef6783f76c57757601010048746ad4d10a562bb53d2ed29438c9dfd0a6cacb78429277072e789d4d8dd8c101010091a52bf4a100e96dba15cbff933df60fcb26d95d6dd9b55fd5e450d5895e4526010100c202dcbdece72a45a1657ff7dbd979b031b1c8b839bc9a3b958683226644b736030100020000000140f6726035b03b90c1f770f0280444eeb041c45d026a8f4baaf00530bdc473a5020000006b483045022100ccdf467aa46d9570c4778f4e68491cc51dff4b815803d2406b6e8772d800f5ad02200ff8f11a59d207c734e9c68154dcef4023d75c37e661ab866b1d3e3ea77e6bda4121021cf99b6763736f48e6e063f99a43bfa82f15111ba0e0f9776280e6bd75d23af9ffffffff0377082800000000001976a91491b21f8856b862ff291ca0ac2ec924ba2419113788ac75330100000000001976a9144b5b285395052a61328b58c6594dd66aa6003d4988acf229f503000000001976a9148efcb6c55f5c299d48d0c74762dd811345c9093b88ac0000000001010200000001bcfe1adc5e99edb82c6a48f44cbae19bc0e5d31f9c8e4b3a92d6befb1cb2e510020000006a4730440220211655b505edd6fe9196aba77477dac5c9f638fe204243c09f1188a19164ac7f022035fb8640750515ca85df8197dec87a76db5c578f05b8ae645e30d8f70d429a324121028bf1be8161c50f98289df3ecd3185ed2273e9d448840232cf2f077f05e789c29ffffffff03d8000400000000001976a9144f427ee5f3099f0ac571f6b723a628e7b08fb64c88ac75330100000000001976a914f7cad87036406e5d3aef5d4a4d65887c76f9466788ac27db1004000000001976a9143219d1b6bd74f932dcb39a5f3b48cfde2b61cc0088ac0000000001020100000002e646efa607ff14299bc0b0cfaa65e035feb493cc440cb8abb8eb6225f8d4c1c4000000006b483045022100b410c4f82655f56fc8de4a622d3e4a8c662198de5ca8963989d70b85734986f502204fe884d99aa6ffd44bb01396b9f63bebcb7222b76e6e26c2bd60837ff555f1f8412103fda4ece7b0c9150872f8ef5241164b36a230fd9657bc43ca083d9e78bc0bcba6ffffffff3275c6dde10d32d61af52b412b1e3956b5cd085605cd521778f11d53849fdb0c000000006a473044022057f9d55ace1945866be0f83431867c58eda32d73ae3fdabed2d3424ebbe493530220553e286ae67bcaf49b0ea1d3163f41b1b3c91702a054e100c1e71ca4927f6dd8412103fda4ece7b0c9150872f8ef5241164b36a230fd9657bc43ca083d9e78bc0bcba6ffffffff04400d0300000000001976a9140e8338fa60e5391d54e99c734640e72461922d9988aca0860100000000001976a9140602787cc457f68c43581224fda6b9555aaab58e88ac10270000000000001976a91402cfbfc3931c7c1cf712574e80e75b1c2df14b2088acd5120000000000001976a914bd3dbab46060873e17ca754b0db0da4552c9a09388ac00000000";

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

test "go-sdk BRC62Hex parses and atomic BEEF round trips" {
    const allocator = std.testing.allocator;

    var beef = try newBeefFromHex(allocator, go_brc62_hex);
    defer beef.deinit();

    try std.testing.expectEqual(BEEF_V1, beef.version);
    try std.testing.expectEqual(@as(usize, 1), beef.bumps.len);
    try std.testing.expectEqual(@as(usize, 2), beef.transactions.count());

    const encoded = try beef.hex();
    defer allocator.free(encoded);
    var roundtrip_beef = try newBeefFromHex(allocator, encoded);
    defer roundtrip_beef.deinit();
    const reencoded = try roundtrip_beef.hex();
    defer allocator.free(reencoded);
    try std.testing.expectEqualStrings(encoded, reencoded);

    const raw = try primitives.hex.decode(allocator, go_brc62_hex);
    defer allocator.free(raw);

    var parsed = try parseBeef(allocator, raw);
    defer parsed.deinit();
    try std.testing.expect(parsed.tx != null);

    var tx = try newTransactionFromBeefHex(allocator, go_brc62_hex);
    defer tx.deinit(allocator);

    const txid = try txidFor(allocator, &tx);
    try std.testing.expectEqual(txid, parsed.txid.?);

    const atomic = try atomicBeefFromTransaction(allocator, &tx);
    defer allocator.free(atomic);

    var reparsed = try newTransactionFromBeef(allocator, atomic);
    defer reparsed.deinit(allocator);
    try std.testing.expectEqual(txid, try txidFor(allocator, &reparsed));
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
    try std.testing.expectEqualSlices(u8, child_bytes, serialized);
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

test "go-sdk BEEFSet parses known counts and transaction lookup" {
    const allocator = std.testing.allocator;

    var beef = try newBeefFromHex(allocator, go_beef_set);
    defer beef.deinit();

    try std.testing.expectEqual(BEEF_V2, beef.version);
    try std.testing.expectEqual(@as(usize, 3), beef.bumps.len);
    try std.testing.expectEqual(@as(usize, 3), beef.transactions.count());

    const target_txid = try primitives.chainhash.Hash.fromHex(
        "b1fc0f44ba629dbdffab9e34fcc4faf9dbde3560a7365c55c26fe4daab052aac",
    );
    const target_tx = beef.findTransaction(target_txid) orelse return error.TestUnexpectedResult;
    try std.testing.expect(target_tx.merkle_path != null);
    try std.testing.expect(beef.findBumpByHash(target_txid) != null);

    var validation = try beef.validateTransactions();
    defer validation.deinit();
    try std.testing.expect(containsHash(validation.valid, target_txid));
    try std.testing.expectEqual(@as(usize, 0), validation.not_valid.len);

    const atomic = try atomicBeefFromTransaction(allocator, target_tx);
    defer allocator.free(atomic);

    var reparsed = try newTransactionFromBeef(allocator, atomic);
    defer reparsed.deinit(allocator);
    try std.testing.expectEqual(target_txid, try txidFor(allocator, &reparsed));
}

fn containsHash(hashes: []const primitives.chainhash.Hash, needle: primitives.chainhash.Hash) bool {
    for (hashes) |hash| {
        if (hash.eql(needle)) return true;
    }
    return false;
}
