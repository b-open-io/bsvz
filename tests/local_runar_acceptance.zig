const std = @import("std");
const bsvz = @import("bsvz");
const harness = @import("support/runar_harness.zig");
const Secp256k1 = std.crypto.ecc.Secp256k1;
const Script = bsvz.script.Script;
const Transaction = bsvz.transaction.Transaction;

const ec_gen_x_hex = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const ec_gen_y_hex = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
const ec_neg_y_hex = "b7c52588d95c3b9aa25b0403f1eef75702e84bb7597aabe663b82f6f04ef2777";
const sha256_init_hex = "6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19";
const blake3_hash_abc_hex = "6f9871b5d6e80fc882e7bb57857f8b279cdc229664eab9382d2838dbf7d8a20d";
const key_one_pub_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const key_two_pub_hex = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const key_one_blake3_hash_hex = "907bc56d3aeb096b40bf82720f3cd180373755d1db074e87047dbbb531dfe187";
const runar_root = "../runar";
const compiler_dist_path = "packages/runar-compiler/dist/index.js";

fn accessOrSkip(rel_path: []const u8) !void {
    std.fs.cwd().access(rel_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return error.SkipZigTest,
        else => return err,
    };
}

fn compileRunarContract(
    allocator: std.mem.Allocator,
    source_rel_path: []const u8,
    file_name: []const u8,
    args_json: []const u8,
) ![]u8 {
    const source_abs_rel = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ runar_root, source_rel_path });
    defer allocator.free(source_abs_rel);
    try accessOrSkip(source_abs_rel);

    const compiler_abs_rel = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ runar_root, compiler_dist_path });
    defer allocator.free(compiler_abs_rel);
    try accessOrSkip(compiler_abs_rel);

    const code = try std.fmt.allocPrint(allocator,
        \\(async () => {{
        \\const {{ compile }} = await import('./packages/runar-compiler/dist/index.js');
        \\const fs = require('fs');
        \\const src = fs.readFileSync('{s}', 'utf-8');
        \\const args = JSON.parse('{s}');
        \\const result = compile(src, {{ fileName: '{s}', constructorArgs: args }});
        \\if (!result.success || !result.scriptHex) {{
        \\  console.error(JSON.stringify(result));
        \\  process.exit(1);
        \\}}
        \\process.stdout.write(result.scriptHex);
        \\}})();
    , .{ source_rel_path, args_json, file_name });
    defer allocator.free(code);

    const run_result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "node", "-e", code },
        .cwd = runar_root,
        .max_output_bytes = 4 * 1024 * 1024,
    }) catch |err| switch (err) {
        error.FileNotFound, error.CurrentWorkingDirectoryUnlinked => return error.SkipZigTest,
        else => return err,
    };
    defer allocator.free(run_result.stderr);

    switch (run_result.term) {
        .Exited => |code_value| {
            if (code_value != 0) {
                std.log.err("runar local compile failed: {s}", .{run_result.stderr});
                allocator.free(run_result.stdout);
                return error.RunarCompileFailed;
            }
        },
        else => {
            allocator.free(run_result.stdout);
            return error.RunarCompileFailed;
        },
    }

    const trimmed = std.mem.trim(u8, run_result.stdout, &std.ascii.whitespace);
    if (trimmed.ptr == run_result.stdout.ptr and trimmed.len == run_result.stdout.len) {
        return run_result.stdout;
    }

    const copy = try allocator.dupe(u8, trimmed);
    allocator.free(run_result.stdout);
    return copy;
}

fn compileInlineRunarContract(
    allocator: std.mem.Allocator,
    source_code: []const u8,
    file_name: []const u8,
    args_json: []const u8,
) ![]u8 {
    const compiler_abs_rel = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ runar_root, compiler_dist_path });
    defer allocator.free(compiler_abs_rel);
    try accessOrSkip(compiler_abs_rel);

    const source_hex = try encodeHexAlloc(allocator, source_code);
    defer allocator.free(source_hex);

    const code = try std.fmt.allocPrint(allocator,
        \\(async () => {{
        \\const {{ compile }} = await import('./packages/runar-compiler/dist/index.js');
        \\const src = Buffer.from('{s}', 'hex').toString('utf8');
        \\const args = JSON.parse('{s}');
        \\const result = compile(src, {{ fileName: '{s}', constructorArgs: args }});
        \\if (!result.success || !result.scriptHex) {{
        \\  console.error(JSON.stringify(result));
        \\  process.exit(1);
        \\}}
        \\process.stdout.write(result.scriptHex);
        \\}})();
    , .{ source_hex, args_json, file_name });
    defer allocator.free(code);

    const run_result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "node", "-e", code },
        .cwd = runar_root,
        .max_output_bytes = 4 * 1024 * 1024,
    }) catch |err| switch (err) {
        error.FileNotFound, error.CurrentWorkingDirectoryUnlinked => return error.SkipZigTest,
        else => return err,
    };
    defer allocator.free(run_result.stderr);

    switch (run_result.term) {
        .Exited => |code_value| {
            if (code_value != 0) {
                std.log.err("runar inline compile failed: {s}", .{run_result.stderr});
                allocator.free(run_result.stdout);
                return error.RunarCompileFailed;
            }
        },
        else => {
            allocator.free(run_result.stdout);
            return error.RunarCompileFailed;
        },
    }

    const trimmed = std.mem.trim(u8, run_result.stdout, &std.ascii.whitespace);
    if (trimmed.ptr == run_result.stdout.ptr and trimmed.len == run_result.stdout.len) {
        return run_result.stdout;
    }

    const copy = try allocator.dupe(u8, trimmed);
    allocator.free(run_result.stdout);
    return copy;
}

fn compileEcPrimitives(allocator: std.mem.Allocator) ![]u8 {
    const args_json = try std.fmt.allocPrint(allocator, "{{\"pt\":\"{s}{s}\"}}", .{
        ec_gen_x_hex,
        ec_gen_y_hex,
    });
    defer allocator.free(args_json);

    return compileRunarContract(
        allocator,
        "conformance/tests/ec-primitives/ec-primitives.runar.ts",
        "ec-primitives.runar.ts",
        args_json,
    );
}

fn encodeHexAlloc(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, bytes.len * 2);
    _ = try bsvz.primitives.hex.encodeLower(bytes, out);
    return out;
}

fn fieldHexAlloc(allocator: std.mem.Allocator, field: anytype) ![]u8 {
    const bytes = field.toBytes(.big);
    return encodeHexAlloc(allocator, &bytes);
}

fn pointHexAlloc(allocator: std.mem.Allocator, point: Secp256k1) ![]u8 {
    const affine = point.affineCoordinates();
    const x_bytes = affine.x.toBytes(.big);
    const y_bytes = affine.y.toBytes(.big);
    var point_bytes: [64]u8 = undefined;
    @memcpy(point_bytes[0..32], &x_bytes);
    @memcpy(point_bytes[32..64], &y_bytes);
    return encodeHexAlloc(allocator, &point_bytes);
}

fn scalarBytes(value: u64) [32]u8 {
    var out = [_]u8{0} ** 32;
    std.mem.writeInt(u64, out[24..32], value, .big);
    return out;
}

const SpendFixtureJson = struct {
    deploy_tx_hex: []const u8,
    call_tx_hex: []const u8,
};

const DirectSpendFixtureJson = struct {
    previous_tx_hex: []const u8,
    call_tx_hex: []const u8,
};

const MultiInputSpendFixtureJson = struct {
    first_previous_tx_hex: []const u8,
    second_previous_tx_hex: []const u8,
    call_tx_hex: []const u8,
};

const ThreeTxFixtureJson = struct {
    deploy_tx_hex: []const u8,
    first_call_tx_hex: []const u8,
    second_call_tx_hex: []const u8,
};

fn buildStatefulCounterFixture(allocator: std.mem.Allocator) !std.json.Parsed(SpendFixtureJson) {
    const source_abs_rel = try std.fmt.allocPrint(allocator, "{s}/{s}", .{
        runar_root,
        "conformance/tests/stateful-counter/stateful-counter.runar.ts",
    });
    defer allocator.free(source_abs_rel);
    try accessOrSkip(source_abs_rel);

    const sdk_abs_rel = try std.fmt.allocPrint(allocator, "{s}/{s}", .{
        runar_root,
        "packages/runar-sdk/dist/index.js",
    });
    defer allocator.free(sdk_abs_rel);
    try accessOrSkip(sdk_abs_rel);

    const code =
        \\(async () => {
        \\  const fs = require('fs');
        \\  const { compile } = await import('./packages/runar-compiler/dist/index.js');
        \\  const { RunarContract, MockProvider, LocalSigner } = await import('./packages/runar-sdk/dist/index.js');
        \\  const source = fs.readFileSync('conformance/tests/stateful-counter/stateful-counter.runar.ts', 'utf-8');
        \\  const result = compile(source, { fileName: 'stateful-counter.runar.ts' });
        \\  if (!result.artifact) {
        \\    console.error(JSON.stringify(result));
        \\    process.exit(1);
        \\  }
        \\  const provider = new MockProvider();
        \\  const signer = new LocalSigner('0000000000000000000000000000000000000000000000000000000000000001');
        \\  const address = await signer.getAddress();
        \\  provider.addUtxo(address, {
        \\    txid: 'aa'.repeat(32),
        \\    outputIndex: 0,
        \\    satoshis: 500000,
        \\    script: '76a914' + '00'.repeat(20) + '88ac',
        \\  });
        \\  const contract = new RunarContract(result.artifact, [0n]);
        \\  await contract.deploy(provider, signer, { satoshis: 50000 });
        \\  await contract.call('increment', [], provider, signer);
        \\  const txs = provider.getBroadcastedTxs();
        \\  process.stdout.write(JSON.stringify({
        \\    deploy_tx_hex: txs[0],
        \\    call_tx_hex: txs[1],
        \\  }));
        \\})();
    ;

    const run_result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "node", "-e", code },
        .cwd = runar_root,
        .max_output_bytes = 512 * 1024,
    }) catch |err| switch (err) {
        error.FileNotFound, error.CurrentWorkingDirectoryUnlinked => return error.SkipZigTest,
        else => return err,
    };
    defer allocator.free(run_result.stderr);
    defer allocator.free(run_result.stdout);

    switch (run_result.term) {
        .Exited => |code_value| {
            if (code_value != 0) {
                std.log.err("stateful counter fixture build failed: {s}", .{run_result.stderr});
                return error.RunarCompileFailed;
            }
        },
        else => return error.RunarCompileFailed,
    }

    return std.json.parseFromSlice(SpendFixtureJson, allocator, run_result.stdout, .{
        .allocate = .alloc_always,
    });
}

fn buildStatefulSignedCounterFixture(allocator: std.mem.Allocator) !std.json.Parsed(SpendFixtureJson) {
    const sdk_abs_rel = try std.fmt.allocPrint(allocator, "{s}/{s}", .{
        runar_root,
        "packages/runar-sdk/dist/index.js",
    });
    defer allocator.free(sdk_abs_rel);
    try accessOrSkip(sdk_abs_rel);

    const code =
        \\(async () => {
        \\  const { compile } = await import('./packages/runar-compiler/dist/index.js');
        \\  const { RunarContract, MockProvider, LocalSigner } = await import('./packages/runar-sdk/dist/index.js');
        \\  const source = `
        \\import { StatefulSmartContract, assert } from 'runar-lang';
        \\import type { Sig, PubKey } from 'runar-lang';
        \\
        \\class Counter extends StatefulSmartContract {
        \\  count: bigint;
        \\  constructor(count: bigint) {
        \\    super(count);
        \\    this.count = count;
        \\  }
        \\
        \\  public increment(sig: Sig, pk: PubKey): void {
        \\    this.count = this.count + 1n;
        \\    assert(checkSig(sig, pk));
        \\  }
        \\
        \\  public reset(sig: Sig, pk: PubKey): void {
        \\    this.count = 0n;
        \\    assert(checkSig(sig, pk));
        \\  }
        \\}`;
        \\  const result = compile(source, { fileName: 'stateful-signed-counter.runar.ts' });
        \\  if (!result.artifact) {
        \\    console.error(JSON.stringify(result));
        \\    process.exit(1);
        \\  }
        \\  const provider = new MockProvider();
        \\  const signer = new LocalSigner('0000000000000000000000000000000000000000000000000000000000000001');
        \\  const address = await signer.getAddress();
        \\  const pubKeyHex = await signer.getPublicKey();
        \\  provider.addUtxo(address, {
        \\    txid: 'bb'.repeat(32),
        \\    outputIndex: 0,
        \\    satoshis: 500000,
        \\    script: '76a914' + '00'.repeat(20) + '88ac',
        \\  });
        \\  const contract = new RunarContract(result.artifact, [5n]);
        \\  await contract.deploy(provider, signer, { satoshis: 50000 });
        \\  await contract.call('reset', [null, pubKeyHex], provider, signer);
        \\  const txs = provider.getBroadcastedTxs();
        \\  process.stdout.write(JSON.stringify({
        \\    deploy_tx_hex: txs[0],
        \\    call_tx_hex: txs[1],
        \\  }));
        \\})();
    ;

    const run_result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "node", "-e", code },
        .cwd = runar_root,
        .max_output_bytes = 512 * 1024,
    }) catch |err| switch (err) {
        error.FileNotFound, error.CurrentWorkingDirectoryUnlinked => return error.SkipZigTest,
        else => return err,
    };
    defer allocator.free(run_result.stderr);
    defer allocator.free(run_result.stdout);

    switch (run_result.term) {
        .Exited => |code_value| {
            if (code_value != 0) {
                std.log.err("stateful signed counter fixture build failed: {s}", .{run_result.stderr});
                return error.RunarCompileFailed;
            }
        },
        else => return error.RunarCompileFailed,
    }

    return std.json.parseFromSlice(SpendFixtureJson, allocator, run_result.stdout, .{
        .allocate = .alloc_always,
    });
}

fn buildCovenantVaultFixture(allocator: std.mem.Allocator) !std.json.Parsed(SpendFixtureJson) {
    const source_abs_rel = try std.fmt.allocPrint(allocator, "{s}/{s}", .{
        runar_root,
        "examples/ts/covenant-vault/CovenantVault.runar.ts",
    });
    defer allocator.free(source_abs_rel);
    try accessOrSkip(source_abs_rel);

    const sdk_abs_rel = try std.fmt.allocPrint(allocator, "{s}/{s}", .{
        runar_root,
        "packages/runar-sdk/dist/index.js",
    });
    defer allocator.free(sdk_abs_rel);
    try accessOrSkip(sdk_abs_rel);

    const code =
        \\(async () => {
        \\  const fs = require('fs');
        \\  const { compile } = await import('./packages/runar-compiler/dist/index.js');
        \\  const { RunarContract, MockProvider, LocalSigner } = await import('./packages/runar-sdk/dist/index.js');
        \\  const { Hash, Utils } = await import('@bsv/sdk');
        \\  const source = fs.readFileSync('examples/ts/covenant-vault/CovenantVault.runar.ts', 'utf-8');
        \\  const result = compile(source, { fileName: 'CovenantVault.runar.ts' });
        \\  if (!result.artifact) {
        \\    console.error(JSON.stringify(result));
        \\    process.exit(1);
        \\  }
        \\  const provider = new MockProvider();
        \\  const signer = new LocalSigner('0000000000000000000000000000000000000000000000000000000000000001');
        \\  const address = await signer.getAddress();
        \\  const pubKeyHex = await signer.getPublicKey();
        \\  const recipientSigner = new LocalSigner('0000000000000000000000000000000000000000000000000000000000000002');
        \\  const recipientPubKey = await recipientSigner.getPublicKey();
        \\  const recipientPKH = Utils.toHex(Hash.hash160(Utils.toArray(recipientPubKey, 'hex')));
        \\  provider.addUtxo(address, {
        \\    txid: 'cc'.repeat(32),
        \\    outputIndex: 0,
        \\    satoshis: 500000,
        \\    script: '76a914' + '00'.repeat(20) + '88ac',
        \\  });
        \\  const contract = new RunarContract(result.artifact, [pubKeyHex, recipientPKH, 1000n]);
        \\  await contract.deploy(provider, signer, { satoshis: 50000 });
        \\  const payoutScript = '76a914' + recipientPKH + '88ac';
        \\  await contract.call('spend', [null, null], provider, signer, {
        \\    terminalOutputs: [{ scriptHex: payoutScript, satoshis: 1000 }],
        \\  });
        \\  const txs = provider.getBroadcastedTxs();
        \\  process.stdout.write(JSON.stringify({
        \\    deploy_tx_hex: txs[0],
        \\    call_tx_hex: txs[1],
        \\  }));
        \\})();
    ;

    const run_result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "node", "-e", code },
        .cwd = runar_root,
        .max_output_bytes = 512 * 1024,
    }) catch |err| switch (err) {
        error.FileNotFound, error.CurrentWorkingDirectoryUnlinked => return error.SkipZigTest,
        else => return err,
    };
    defer allocator.free(run_result.stderr);
    defer allocator.free(run_result.stdout);

    switch (run_result.term) {
        .Exited => |code_value| {
            if (code_value != 0) {
                std.log.err("covenant vault fixture build failed: {s}", .{run_result.stderr});
                return error.RunarCompileFailed;
            }
        },
        else => return error.RunarCompileFailed,
    }

    return std.json.parseFromSlice(SpendFixtureJson, allocator, run_result.stdout, .{
        .allocate = .alloc_always,
    });
}

fn buildCovenantVaultWrongAmountFixture(allocator: std.mem.Allocator) !std.json.Parsed(SpendFixtureJson) {
    const source_abs_rel = try std.fmt.allocPrint(allocator, "{s}/{s}", .{
        runar_root,
        "examples/ts/covenant-vault/CovenantVault.runar.ts",
    });
    defer allocator.free(source_abs_rel);
    try accessOrSkip(source_abs_rel);

    const sdk_abs_rel = try std.fmt.allocPrint(allocator, "{s}/{s}", .{
        runar_root,
        "packages/runar-sdk/dist/index.js",
    });
    defer allocator.free(sdk_abs_rel);
    try accessOrSkip(sdk_abs_rel);

    const code =
        \\(async () => {
        \\  const fs = require('fs');
        \\  const { compile } = await import('./packages/runar-compiler/dist/index.js');
        \\  const { RunarContract, MockProvider, LocalSigner } = await import('./packages/runar-sdk/dist/index.js');
        \\  const { Hash, Utils } = await import('@bsv/sdk');
        \\  const source = fs.readFileSync('examples/ts/covenant-vault/CovenantVault.runar.ts', 'utf-8');
        \\  const result = compile(source, { fileName: 'CovenantVault.runar.ts' });
        \\  if (!result.artifact) {
        \\    console.error(JSON.stringify(result));
        \\    process.exit(1);
        \\  }
        \\  const provider = new MockProvider();
        \\  const signer = new LocalSigner('0000000000000000000000000000000000000000000000000000000000000001');
        \\  const address = await signer.getAddress();
        \\  const pubKeyHex = await signer.getPublicKey();
        \\  const recipientSigner = new LocalSigner('0000000000000000000000000000000000000000000000000000000000000002');
        \\  const recipientPubKey = await recipientSigner.getPublicKey();
        \\  const recipientPKH = Utils.toHex(Hash.hash160(Utils.toArray(recipientPubKey, 'hex')));
        \\  provider.addUtxo(address, {
        \\    txid: 'cd'.repeat(32),
        \\    outputIndex: 0,
        \\    satoshis: 500000,
        \\    script: '76a914' + '00'.repeat(20) + '88ac',
        \\  });
        \\  const contract = new RunarContract(result.artifact, [pubKeyHex, recipientPKH, 1000n]);
        \\  await contract.deploy(provider, signer, { satoshis: 50000 });
        \\  const payoutScript = '76a914' + recipientPKH + '88ac';
        \\  await contract.call('spend', [null, null], provider, signer, {
        \\    terminalOutputs: [{ scriptHex: payoutScript, satoshis: 999 }],
        \\  });
        \\  const txs = provider.getBroadcastedTxs();
        \\  process.stdout.write(JSON.stringify({
        \\    deploy_tx_hex: txs[0],
        \\    call_tx_hex: txs[1],
        \\  }));
        \\})();
    ;

    const run_result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "node", "-e", code },
        .cwd = runar_root,
        .max_output_bytes = 512 * 1024,
    }) catch |err| switch (err) {
        error.FileNotFound, error.CurrentWorkingDirectoryUnlinked => return error.SkipZigTest,
        else => return err,
    };
    defer allocator.free(run_result.stderr);
    defer allocator.free(run_result.stdout);

    switch (run_result.term) {
        .Exited => |code_value| {
            if (code_value != 0) {
                std.log.err("covenant vault wrong-amount fixture build failed: {s}", .{run_result.stderr});
                return error.RunarCompileFailed;
            }
        },
        else => return error.RunarCompileFailed,
    }

    return std.json.parseFromSlice(SpendFixtureJson, allocator, run_result.stdout, .{
        .allocate = .alloc_always,
    });
}

fn buildAuctionBidFixture(allocator: std.mem.Allocator) !std.json.Parsed(SpendFixtureJson) {
    const source_abs_rel = try std.fmt.allocPrint(allocator, "{s}/{s}", .{
        runar_root,
        "examples/ts/auction/Auction.runar.ts",
    });
    defer allocator.free(source_abs_rel);
    try accessOrSkip(source_abs_rel);

    const sdk_abs_rel = try std.fmt.allocPrint(allocator, "{s}/{s}", .{
        runar_root,
        "packages/runar-sdk/dist/index.js",
    });
    defer allocator.free(sdk_abs_rel);
    try accessOrSkip(sdk_abs_rel);

    const code =
        \\(async () => {
        \\  const fs = require('fs');
        \\  const { compile } = await import('./packages/runar-compiler/dist/index.js');
        \\  const { RunarContract, MockProvider, LocalSigner } = await import('./packages/runar-sdk/dist/index.js');
        \\  const source = fs.readFileSync('examples/ts/auction/Auction.runar.ts', 'utf-8');
        \\  const result = compile(source, { fileName: 'Auction.runar.ts' });
        \\  if (!result.artifact) {
        \\    console.error(JSON.stringify(result));
        \\    process.exit(1);
        \\  }
        \\  const provider = new MockProvider();
        \\  const auctioneerSigner = new LocalSigner('0000000000000000000000000000000000000000000000000000000000000001');
        \\  const bidderSigner = new LocalSigner('0000000000000000000000000000000000000000000000000000000000000002');
        \\  const auctioneerAddress = await auctioneerSigner.getAddress();
        \\  const auctioneerPubKey = await auctioneerSigner.getPublicKey();
        \\  const bidderAddress = await bidderSigner.getAddress();
        \\  const bidderPubKey = await bidderSigner.getPublicKey();
        \\  provider.addUtxo(auctioneerAddress, {
        \\    txid: 'dd'.repeat(32),
        \\    outputIndex: 0,
        \\    satoshis: 500000,
        \\    script: '76a914' + '00'.repeat(20) + '88ac',
        \\  });
        \\  provider.addUtxo(bidderAddress, {
        \\    txid: 'ee'.repeat(32),
        \\    outputIndex: 0,
        \\    satoshis: 500000,
        \\    script: '76a914' + '00'.repeat(20) + '88ac',
        \\  });
        \\  const contract = new RunarContract(result.artifact, [
        \\    auctioneerPubKey,
        \\    auctioneerPubKey,
        \\    100n,
        \\    999999999n,
        \\  ]);
        \\  await contract.deploy(provider, auctioneerSigner, { satoshis: 50000 });
        \\  await contract.call('bid', [null, bidderPubKey, 200n], provider, bidderSigner);
        \\  const txs = provider.getBroadcastedTxs();
        \\  process.stdout.write(JSON.stringify({
        \\    deploy_tx_hex: txs[0],
        \\    call_tx_hex: txs[1],
        \\  }));
        \\})();
    ;

    const run_result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "node", "-e", code },
        .cwd = runar_root,
        .max_output_bytes = 512 * 1024,
    }) catch |err| switch (err) {
        error.FileNotFound, error.CurrentWorkingDirectoryUnlinked => return error.SkipZigTest,
        else => return err,
    };
    defer allocator.free(run_result.stderr);
    defer allocator.free(run_result.stdout);

    switch (run_result.term) {
        .Exited => |code_value| {
            if (code_value != 0) {
                std.log.err("auction bid fixture build failed: {s}", .{run_result.stderr});
                return error.RunarCompileFailed;
            }
        },
        else => return error.RunarCompileFailed,
    }

    return std.json.parseFromSlice(SpendFixtureJson, allocator, run_result.stdout, .{
        .allocate = .alloc_always,
    });
}

fn buildAuctionCloseFixture(allocator: std.mem.Allocator, deadline: u64) !std.json.Parsed(SpendFixtureJson) {
    const source_abs_rel = try std.fmt.allocPrint(allocator, "{s}/{s}", .{
        runar_root,
        "examples/ts/auction/Auction.runar.ts",
    });
    defer allocator.free(source_abs_rel);
    try accessOrSkip(source_abs_rel);

    const sdk_abs_rel = try std.fmt.allocPrint(allocator, "{s}/{s}", .{
        runar_root,
        "packages/runar-sdk/dist/index.js",
    });
    defer allocator.free(sdk_abs_rel);
    try accessOrSkip(sdk_abs_rel);

    const code = try std.fmt.allocPrint(allocator,
        \\(async () => {{
        \\  const fs = require('fs');
        \\  const {{ compile }} = await import('./packages/runar-compiler/dist/index.js');
        \\  const {{ RunarContract, MockProvider, LocalSigner }} = await import('./packages/runar-sdk/dist/index.js');
        \\  const source = fs.readFileSync('examples/ts/auction/Auction.runar.ts', 'utf-8');
        \\  const result = compile(source, {{ fileName: 'Auction.runar.ts' }});
        \\  if (!result.artifact) {{
        \\    console.error(JSON.stringify(result));
        \\    process.exit(1);
        \\  }}
        \\  const provider = new MockProvider();
        \\  const auctioneerSigner = new LocalSigner('0000000000000000000000000000000000000000000000000000000000000001');
        \\  const bidderSigner = new LocalSigner('0000000000000000000000000000000000000000000000000000000000000002');
        \\  const auctioneerAddress = await auctioneerSigner.getAddress();
        \\  const auctioneerPubKey = await auctioneerSigner.getPublicKey();
        \\  const bidderPubKey = await bidderSigner.getPublicKey();
        \\  provider.addUtxo(auctioneerAddress, {{
        \\    txid: 'de'.repeat(32),
        \\    outputIndex: 0,
        \\    satoshis: 500000,
        \\    script: '76a914' + '00'.repeat(20) + '88ac',
        \\  }});
        \\  const contract = new RunarContract(result.artifact, [
        \\    auctioneerPubKey,
        \\    bidderPubKey,
        \\    100n,
        \\    {d}n,
        \\  ]);
        \\  await contract.deploy(provider, auctioneerSigner, {{ satoshis: 50000 }});
        \\  await contract.call('close', [null], provider, auctioneerSigner);
        \\  const txs = provider.getBroadcastedTxs();
        \\  process.stdout.write(JSON.stringify({{
        \\    deploy_tx_hex: txs[0],
        \\    call_tx_hex: txs[1],
        \\  }}));
        \\}})();
    , .{deadline});
    defer allocator.free(code);

    const run_result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "node", "-e", code },
        .cwd = runar_root,
        .max_output_bytes = 512 * 1024,
    }) catch |err| switch (err) {
        error.FileNotFound, error.CurrentWorkingDirectoryUnlinked => return error.SkipZigTest,
        else => return err,
    };
    defer allocator.free(run_result.stderr);
    defer allocator.free(run_result.stdout);

    switch (run_result.term) {
        .Exited => |code_value| {
            if (code_value != 0) {
                std.log.err("auction close fixture build failed: {s}", .{run_result.stderr});
                return error.RunarCompileFailed;
            }
        },
        else => return error.RunarCompileFailed,
    }

    return std.json.parseFromSlice(SpendFixtureJson, allocator, run_result.stdout, .{
        .allocate = .alloc_always,
    });
}

fn buildAuctionTwoBidFixture(allocator: std.mem.Allocator) !std.json.Parsed(ThreeTxFixtureJson) {
    const source_abs_rel = try std.fmt.allocPrint(allocator, "{s}/{s}", .{
        runar_root,
        "examples/ts/auction/Auction.runar.ts",
    });
    defer allocator.free(source_abs_rel);
    try accessOrSkip(source_abs_rel);

    const sdk_abs_rel = try std.fmt.allocPrint(allocator, "{s}/{s}", .{
        runar_root,
        "packages/runar-sdk/dist/index.js",
    });
    defer allocator.free(sdk_abs_rel);
    try accessOrSkip(sdk_abs_rel);

    const code =
        \\(async () => {
        \\  const fs = require('fs');
        \\  const { compile } = await import('./packages/runar-compiler/dist/index.js');
        \\  const { RunarContract, MockProvider, LocalSigner } = await import('./packages/runar-sdk/dist/index.js');
        \\  const source = fs.readFileSync('examples/ts/auction/Auction.runar.ts', 'utf-8');
        \\  const result = compile(source, { fileName: 'Auction.runar.ts' });
        \\  if (!result.artifact) {
        \\    console.error(JSON.stringify(result));
        \\    process.exit(1);
        \\  }
        \\  const provider = new MockProvider();
        \\  const auctioneerSigner = new LocalSigner('0000000000000000000000000000000000000000000000000000000000000001');
        \\  const bidderOneSigner = new LocalSigner('0000000000000000000000000000000000000000000000000000000000000002');
        \\  const bidderTwoSigner = new LocalSigner('0000000000000000000000000000000000000000000000000000000000000003');
        \\  const auctioneerAddress = await auctioneerSigner.getAddress();
        \\  const auctioneerPubKey = await auctioneerSigner.getPublicKey();
        \\  const bidderOneAddress = await bidderOneSigner.getAddress();
        \\  const bidderOnePubKey = await bidderOneSigner.getPublicKey();
        \\  const bidderTwoAddress = await bidderTwoSigner.getAddress();
        \\  const bidderTwoPubKey = await bidderTwoSigner.getPublicKey();
        \\  provider.addUtxo(auctioneerAddress, {
        \\    txid: 'f0'.repeat(32),
        \\    outputIndex: 0,
        \\    satoshis: 500000,
        \\    script: '76a914' + '00'.repeat(20) + '88ac',
        \\  });
        \\  provider.addUtxo(bidderOneAddress, {
        \\    txid: 'f1'.repeat(32),
        \\    outputIndex: 0,
        \\    satoshis: 500000,
        \\    script: '76a914' + '00'.repeat(20) + '88ac',
        \\  });
        \\  provider.addUtxo(bidderTwoAddress, {
        \\    txid: 'f2'.repeat(32),
        \\    outputIndex: 0,
        \\    satoshis: 500000,
        \\    script: '76a914' + '00'.repeat(20) + '88ac',
        \\  });
        \\  const contract = new RunarContract(result.artifact, [
        \\    auctioneerPubKey,
        \\    auctioneerPubKey,
        \\    100n,
        \\    999999999n,
        \\  ]);
        \\  await contract.deploy(provider, auctioneerSigner, { satoshis: 50000 });
        \\  await contract.call('bid', [null, bidderOnePubKey, 200n], provider, bidderOneSigner);
        \\  await contract.call('bid', [null, bidderTwoPubKey, 300n], provider, bidderTwoSigner);
        \\  const txs = provider.getBroadcastedTxs();
        \\  process.stdout.write(JSON.stringify({
        \\    deploy_tx_hex: txs[0],
        \\    first_call_tx_hex: txs[1],
        \\    second_call_tx_hex: txs[2],
        \\  }));
        \\})();
    ;

    const run_result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "node", "-e", code },
        .cwd = runar_root,
        .max_output_bytes = 1024 * 1024,
    }) catch |err| switch (err) {
        error.FileNotFound, error.CurrentWorkingDirectoryUnlinked => return error.SkipZigTest,
        else => return err,
    };
    defer allocator.free(run_result.stderr);
    defer allocator.free(run_result.stdout);

    switch (run_result.term) {
        .Exited => |code_value| {
            if (code_value != 0) {
                std.log.err("auction two-bid fixture build failed: {s}", .{run_result.stderr});
                return error.RunarCompileFailed;
            }
        },
        else => return error.RunarCompileFailed,
    }

    return std.json.parseFromSlice(ThreeTxFixtureJson, allocator, run_result.stdout, .{
        .allocate = .alloc_always,
    });
}

fn buildNftTransferBurnFixture(allocator: std.mem.Allocator) !std.json.Parsed(ThreeTxFixtureJson) {
    const source_abs_rel = try std.fmt.allocPrint(allocator, "{s}/{s}", .{
        runar_root,
        "examples/ts/token-nft/NFTExample.runar.ts",
    });
    defer allocator.free(source_abs_rel);
    try accessOrSkip(source_abs_rel);

    const sdk_abs_rel = try std.fmt.allocPrint(allocator, "{s}/{s}", .{
        runar_root,
        "packages/runar-sdk/dist/index.js",
    });
    defer allocator.free(sdk_abs_rel);
    try accessOrSkip(sdk_abs_rel);

    const code =
        \\(async () => {
        \\  const fs = require('fs');
        \\  const { compile } = await import('./packages/runar-compiler/dist/index.js');
        \\  const { RunarContract, MockProvider, LocalSigner } = await import('./packages/runar-sdk/dist/index.js');
        \\  const source = fs.readFileSync('examples/ts/token-nft/NFTExample.runar.ts', 'utf-8');
        \\  const result = compile(source, { fileName: 'NFTExample.runar.ts' });
        \\  if (!result.artifact) {
        \\    console.error(JSON.stringify(result));
        \\    process.exit(1);
        \\  }
        \\  const provider = new MockProvider();
        \\  const ownerSigner = new LocalSigner('0000000000000000000000000000000000000000000000000000000000000001');
        \\  const newOwnerSigner = new LocalSigner('0000000000000000000000000000000000000000000000000000000000000002');
        \\  const ownerAddress = await ownerSigner.getAddress();
        \\  const ownerPubKey = await ownerSigner.getPublicKey();
        \\  const newOwnerPubKey = await newOwnerSigner.getPublicKey();
        \\  provider.addUtxo(ownerAddress, {
        \\    txid: 'ab'.repeat(32),
        \\    outputIndex: 0,
        \\    satoshis: 500000,
        \\    script: '76a914' + '00'.repeat(20) + '88ac',
        \\  });
        \\  const contract = new RunarContract(result.artifact, [
        \\    ownerPubKey,
        \\    Buffer.from('NFT-LOCAL-001').toString('hex'),
        \\    Buffer.from('local acceptance').toString('hex'),
        \\  ]);
        \\  await contract.deploy(provider, ownerSigner, { satoshis: 5000 });
        \\  await contract.call('transfer', [null, newOwnerPubKey, 5000n], provider, ownerSigner);
        \\  await contract.call('burn', [null], provider, newOwnerSigner);
        \\  const txs = provider.getBroadcastedTxs();
        \\  process.stdout.write(JSON.stringify({
        \\    deploy_tx_hex: txs[0],
        \\    first_call_tx_hex: txs[1],
        \\    second_call_tx_hex: txs[2],
        \\  }));
        \\})();
    ;

    const run_result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "node", "-e", code },
        .cwd = runar_root,
        .max_output_bytes = 1024 * 1024,
    }) catch |err| switch (err) {
        error.FileNotFound, error.CurrentWorkingDirectoryUnlinked => return error.SkipZigTest,
        else => return err,
    };
    defer allocator.free(run_result.stderr);
    defer allocator.free(run_result.stdout);

    switch (run_result.term) {
        .Exited => |code_value| {
            if (code_value != 0) {
                std.log.err("nft transfer/burn fixture build failed: {s}", .{run_result.stderr});
                return error.RunarCompileFailed;
            }
        },
        else => return error.RunarCompileFailed,
    }

    return std.json.parseFromSlice(ThreeTxFixtureJson, allocator, run_result.stdout, .{
        .allocate = .alloc_always,
    });
}

fn buildMathDemoExponentiateLog2Fixture(allocator: std.mem.Allocator) !std.json.Parsed(ThreeTxFixtureJson) {
    const source_abs_rel = try std.fmt.allocPrint(allocator, "{s}/{s}", .{
        runar_root,
        "conformance/tests/math-demo/math-demo.runar.ts",
    });
    defer allocator.free(source_abs_rel);
    try accessOrSkip(source_abs_rel);

    const sdk_abs_rel = try std.fmt.allocPrint(allocator, "{s}/{s}", .{
        runar_root,
        "packages/runar-sdk/dist/index.js",
    });
    defer allocator.free(sdk_abs_rel);
    try accessOrSkip(sdk_abs_rel);

    const code =
        \\(async () => {
        \\  const fs = require('fs');
        \\  const { compile } = await import('./packages/runar-compiler/dist/index.js');
        \\  const { RunarContract, MockProvider, LocalSigner } = await import('./packages/runar-sdk/dist/index.js');
        \\  const source = fs.readFileSync('conformance/tests/math-demo/math-demo.runar.ts', 'utf-8');
        \\  const result = compile(source, { fileName: 'math-demo.runar.ts' });
        \\  if (!result.artifact) {
        \\    console.error(JSON.stringify(result));
        \\    process.exit(1);
        \\  }
        \\  const provider = new MockProvider();
        \\  const signer = new LocalSigner('0000000000000000000000000000000000000000000000000000000000000001');
        \\  const address = await signer.getAddress();
        \\  provider.addUtxo(address, {
        \\    txid: 'bc'.repeat(32),
        \\    outputIndex: 0,
        \\    satoshis: 500000,
        \\    script: '76a914' + '00'.repeat(20) + '88ac',
        \\  });
        \\  const contract = new RunarContract(result.artifact, [2n]);
        \\  await contract.deploy(provider, signer, { satoshis: 5000 });
        \\  await contract.call('exponentiate', [10n], provider, signer);
        \\  await contract.call('computeLog2', [], provider, signer);
        \\  const txs = provider.getBroadcastedTxs();
        \\  process.stdout.write(JSON.stringify({
        \\    deploy_tx_hex: txs[0],
        \\    first_call_tx_hex: txs[1],
        \\    second_call_tx_hex: txs[2],
        \\  }));
        \\})();
    ;

    const run_result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "node", "-e", code },
        .cwd = runar_root,
        .max_output_bytes = 1024 * 1024,
    }) catch |err| switch (err) {
        error.FileNotFound, error.CurrentWorkingDirectoryUnlinked => return error.SkipZigTest,
        else => return err,
    };
    defer allocator.free(run_result.stderr);
    defer allocator.free(run_result.stdout);

    switch (run_result.term) {
        .Exited => |code_value| {
            if (code_value != 0) {
                std.log.err("math-demo exponentiate/log2 fixture build failed: {s}", .{run_result.stderr});
                return error.RunarCompileFailed;
            }
        },
        else => return error.RunarCompileFailed,
    }

    return std.json.parseFromSlice(ThreeTxFixtureJson, allocator, run_result.stdout, .{
        .allocate = .alloc_always,
    });
}

fn buildSha256CompressFixture(allocator: std.mem.Allocator) !std.json.Parsed(SpendFixtureJson) {
    const source_abs_rel = try std.fmt.allocPrint(allocator, "{s}/{s}", .{
        runar_root,
        "examples/ts/sha256-compress/Sha256CompressTest.runar.ts",
    });
    defer allocator.free(source_abs_rel);
    try accessOrSkip(source_abs_rel);

    const sdk_abs_rel = try std.fmt.allocPrint(allocator, "{s}/{s}", .{
        runar_root,
        "packages/runar-sdk/dist/index.js",
    });
    defer allocator.free(sdk_abs_rel);
    try accessOrSkip(sdk_abs_rel);

    const code =
        \\(async () => {
        \\  const fs = require('fs');
        \\  const { compile } = await import('./packages/runar-compiler/dist/index.js');
        \\  const { RunarContract, MockProvider, LocalSigner } = await import('./packages/runar-sdk/dist/index.js');
        \\  const source = fs.readFileSync('examples/ts/sha256-compress/Sha256CompressTest.runar.ts', 'utf-8');
        \\  const result = compile(source, {
        \\    fileName: 'Sha256CompressTest.runar.ts',
        \\    constructorArgs: {
        \\      expected: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
        \\    },
        \\  });
        \\  if (!result.artifact) {
        \\    console.error(JSON.stringify(result));
        \\    process.exit(1);
        \\  }
        \\  const provider = new MockProvider();
        \\  const signer = new LocalSigner('0000000000000000000000000000000000000000000000000000000000000001');
        \\  const address = await signer.getAddress();
        \\  provider.addUtxo(address, {
        \\    txid: 'cd'.repeat(32),
        \\    outputIndex: 0,
        \\    satoshis: 1000000,
        \\    script: '76a914' + '00'.repeat(20) + '88ac',
        \\  });
        \\  const contract = new RunarContract(result.artifact, [
        \\    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
        \\  ]);
        \\  await contract.deploy(provider, signer, { satoshis: 500000 });
        \\  await contract.call(
        \\    'verify',
        \\    [
        \\      '6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19',
        \\      '6162638000000000000000000000000000000000000000000000000000000000' +
        \\      '0000000000000000000000000000000000000000000000000000000000000018',
        \\    ],
        \\    provider,
        \\    signer,
        \\  );
        \\  const txs = provider.getBroadcastedTxs();
        \\  process.stdout.write(JSON.stringify({
        \\    deploy_tx_hex: txs[0],
        \\    call_tx_hex: txs[1],
        \\  }));
        \\})();
    ;

    const run_result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "node", "-e", code },
        .cwd = runar_root,
        .max_output_bytes = 2 * 1024 * 1024,
    }) catch |err| switch (err) {
        error.FileNotFound, error.CurrentWorkingDirectoryUnlinked => return error.SkipZigTest,
        else => return err,
    };
    defer allocator.free(run_result.stderr);
    defer allocator.free(run_result.stdout);

    switch (run_result.term) {
        .Exited => |code_value| {
            if (code_value != 0) {
                std.log.err("sha256 compress fixture build failed: {s}", .{run_result.stderr});
                return error.RunarCompileFailed;
            }
        },
        else => return error.RunarCompileFailed,
    }

    return std.json.parseFromSlice(SpendFixtureJson, allocator, run_result.stdout, .{
        .allocate = .alloc_always,
    });
}

fn buildFungibleTokenTransferFixture(allocator: std.mem.Allocator) !std.json.Parsed(SpendFixtureJson) {
    const source_abs_rel = try std.fmt.allocPrint(allocator, "{s}/{s}", .{
        runar_root,
        "examples/ts/token-ft/FungibleTokenExample.runar.ts",
    });
    defer allocator.free(source_abs_rel);
    try accessOrSkip(source_abs_rel);

    const sdk_abs_rel = try std.fmt.allocPrint(allocator, "{s}/{s}", .{
        runar_root,
        "packages/runar-sdk/dist/index.js",
    });
    defer allocator.free(sdk_abs_rel);
    try accessOrSkip(sdk_abs_rel);

    const code =
        \\(async () => {
        \\  const fs = require('fs');
        \\  const { compile } = await import('./packages/runar-compiler/dist/index.js');
        \\  const { RunarContract, MockProvider, LocalSigner } = await import('./packages/runar-sdk/dist/index.js');
        \\  const source = fs.readFileSync('examples/ts/token-ft/FungibleTokenExample.runar.ts', 'utf-8');
        \\  const result = compile(source, { fileName: 'FungibleTokenExample.runar.ts' });
        \\  if (!result.artifact) {
        \\    console.error(JSON.stringify(result));
        \\    process.exit(1);
        \\  }
        \\  const provider = new MockProvider();
        \\  const signer = new LocalSigner('0000000000000000000000000000000000000000000000000000000000000001');
        \\  const recipientSigner = new LocalSigner('0000000000000000000000000000000000000000000000000000000000000002');
        \\  const address = await signer.getAddress();
        \\  const pubKeyHex = await signer.getPublicKey();
        \\  const recipientPubKey = await recipientSigner.getPublicKey();
        \\  provider.addUtxo(address, {
        \\    txid: 'ce'.repeat(32),
        \\    outputIndex: 0,
        \\    satoshis: 1000000,
        \\    script: '76a914' + '00'.repeat(20) + '88ac',
        \\  });
        \\  const contract = new RunarContract(result.artifact, [
        \\    pubKeyHex,
        \\    1000n,
        \\    0n,
        \\    Buffer.from('FT-LOCAL-001').toString('hex'),
        \\  ]);
        \\  await contract.deploy(provider, signer, { satoshis: 5000 });
        \\  await contract.call(
        \\    'transfer',
        \\    [null, recipientPubKey, 300n, 1n],
        \\    provider,
        \\    signer,
        \\    {
        \\      outputs: [
        \\        { satoshis: 1, state: { owner: recipientPubKey, balance: 300n, mergeBalance: 0n } },
        \\        { satoshis: 1, state: { owner: pubKeyHex, balance: 700n, mergeBalance: 0n } },
        \\      ],
        \\    },
        \\  );
        \\  const txs = provider.getBroadcastedTxs();
        \\  process.stdout.write(JSON.stringify({
        \\    deploy_tx_hex: txs[0],
        \\    call_tx_hex: txs[1],
        \\  }));
        \\})();
    ;

    const run_result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "node", "-e", code },
        .cwd = runar_root,
        .max_output_bytes = 2 * 1024 * 1024,
    }) catch |err| switch (err) {
        error.FileNotFound, error.CurrentWorkingDirectoryUnlinked => return error.SkipZigTest,
        else => return err,
    };
    defer allocator.free(run_result.stderr);
    defer allocator.free(run_result.stdout);

    switch (run_result.term) {
        .Exited => |code_value| {
            if (code_value != 0) {
                std.log.err("fungible token transfer fixture build failed: {s}", .{run_result.stderr});
                return error.RunarCompileFailed;
            }
        },
        else => return error.RunarCompileFailed,
    }

    return std.json.parseFromSlice(SpendFixtureJson, allocator, run_result.stdout, .{
        .allocate = .alloc_always,
    });
}

fn buildEscrowFixture(
    allocator: std.mem.Allocator,
    method_name: []const u8,
    signer_zero_hex: []const u8,
    signer_one_hex: []const u8,
    funding_txid_hex: []const u8,
) !std.json.Parsed(SpendFixtureJson) {
    const source_abs_rel = try std.fmt.allocPrint(allocator, "{s}/{s}", .{
        runar_root,
        "examples/ts/escrow/Escrow.runar.ts",
    });
    defer allocator.free(source_abs_rel);
    try accessOrSkip(source_abs_rel);

    const sdk_abs_rel = try std.fmt.allocPrint(allocator, "{s}/{s}", .{
        runar_root,
        "packages/runar-sdk/dist/index.js",
    });
    defer allocator.free(sdk_abs_rel);
    try accessOrSkip(sdk_abs_rel);

    const code = try std.fmt.allocPrint(allocator,
        \\(async () => {{
        \\  const fs = require('fs');
        \\  const {{ compile }} = await import('./packages/runar-compiler/dist/index.js');
        \\  const {{ RunarContract, MockProvider, LocalSigner }} = await import('./packages/runar-sdk/dist/index.js');
        \\  const source = fs.readFileSync('examples/ts/escrow/Escrow.runar.ts', 'utf-8');
        \\  const result = compile(source, {{ fileName: 'Escrow.runar.ts' }});
        \\  if (!result.artifact) {{
        \\    console.error(JSON.stringify(result));
        \\    process.exit(1);
        \\  }}
        \\  const provider = new MockProvider();
        \\  const buyer = new LocalSigner('0000000000000000000000000000000000000000000000000000000000000001');
        \\  const seller = new LocalSigner('0000000000000000000000000000000000000000000000000000000000000002');
        \\  const arbiter = new LocalSigner('0000000000000000000000000000000000000000000000000000000000000003');
        \\  const buyerPub = await buyer.getPublicKey();
        \\  const sellerPub = await seller.getPublicKey();
        \\  const arbiterPub = await arbiter.getPublicKey();
        \\  const buyerAddr = await buyer.getAddress();
        \\  provider.addUtxo(buyerAddr, {{
        \\    txid: '{s}',
        \\    outputIndex: 0,
        \\    satoshis: 500000,
        \\    script: '76a914' + '00'.repeat(20) + '88ac',
        \\  }});
        \\  const contract = new RunarContract(result.artifact, [buyerPub, sellerPub, arbiterPub]);
        \\  contract.connect(provider, buyer);
        \\  await contract.deploy(provider, buyer, {{ satoshis: 75000 }});
        \\  const prepared = await contract.prepareCall('{s}', [null, null]);
        \\  const txHex = prepared.tx.toHex();
        \\  const lockingScript = contract.getLockingScript();
        \\  const sig0 = await (new LocalSigner('{s}')).sign(txHex, 0, lockingScript, 75000);
        \\  const sig1 = await (new LocalSigner('{s}')).sign(txHex, 0, lockingScript, 75000);
        \\  await contract.finalizeCall(prepared, {{ 0: sig0, 1: sig1 }});
        \\  const txs = provider.getBroadcastedTxs();
        \\  process.stdout.write(JSON.stringify({{
        \\    deploy_tx_hex: txs[0],
        \\    call_tx_hex: txs[1],
        \\  }}));
        \\}})();
    , .{ funding_txid_hex, method_name, signer_zero_hex, signer_one_hex });
    defer allocator.free(code);

    const run_result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "node", "-e", code },
        .cwd = runar_root,
        .max_output_bytes = 1024 * 1024,
    }) catch |err| switch (err) {
        error.FileNotFound, error.CurrentWorkingDirectoryUnlinked => return error.SkipZigTest,
        else => return err,
    };
    defer allocator.free(run_result.stderr);
    defer allocator.free(run_result.stdout);

    switch (run_result.term) {
        .Exited => |code_value| {
            if (code_value != 0) {
                std.log.err("escrow fixture build failed ({s}): {s}", .{ method_name, run_result.stderr });
                return error.RunarCompileFailed;
            }
        },
        else => return error.RunarCompileFailed,
    }

    return std.json.parseFromSlice(SpendFixtureJson, allocator, run_result.stdout, .{
        .allocate = .alloc_always,
    });
}

fn buildTicTacToeMoveAndWinFixture(allocator: std.mem.Allocator) !std.json.Parsed(DirectSpendFixtureJson) {
    const source_abs_rel = try std.fmt.allocPrint(allocator, "{s}/{s}", .{
        runar_root,
        "examples/ts/tic-tac-toe/TicTacToe.runar.ts",
    });
    defer allocator.free(source_abs_rel);
    try accessOrSkip(source_abs_rel);

    const sdk_abs_rel = try std.fmt.allocPrint(allocator, "{s}/{s}", .{
        runar_root,
        "packages/runar-sdk/dist/index.js",
    });
    defer allocator.free(sdk_abs_rel);
    try accessOrSkip(sdk_abs_rel);

    const code =
        \\(async () => {
        \\  const fs = require('fs');
        \\  const { compile } = await import('./packages/runar-compiler/dist/index.js');
        \\  const { RunarContract, MockProvider, LocalSigner } = await import('./packages/runar-sdk/dist/index.js');
        \\  const { Hash, Utils } = await import('@bsv/sdk');
        \\  const source = fs.readFileSync('examples/ts/tic-tac-toe/TicTacToe.runar.ts', 'utf-8');
        \\  const result = compile(source, { fileName: 'TicTacToe.runar.ts' });
        \\  if (!result.artifact) {
        \\    console.error(JSON.stringify(result));
        \\    process.exit(1);
        \\  }
        \\  const provider = new MockProvider();
        \\  const playerX = new LocalSigner('0000000000000000000000000000000000000000000000000000000000000003');
        \\  const playerO = new LocalSigner('0000000000000000000000000000000000000000000000000000000000000005');
        \\  const playerXPub = await playerX.getPublicKey();
        \\  const playerOPub = await playerO.getPublicKey();
        \\  const playerXAddr = await playerX.getAddress();
        \\  const playerOAddr = await playerO.getAddress();
        \\  provider.addUtxo(playerXAddr, {
        \\    txid: '13'.repeat(32),
        \\    outputIndex: 0,
        \\    satoshis: 500000,
        \\    script: '76a914' + '00'.repeat(20) + '88ac',
        \\  });
        \\  provider.addUtxo(playerOAddr, {
        \\    txid: '15'.repeat(32),
        \\    outputIndex: 0,
        \\    satoshis: 500000,
        \\    script: '76a914' + '00'.repeat(20) + '88ac',
        \\  });
        \\  const betAmount = 1000;
        \\  const contract = new RunarContract(result.artifact, [playerXPub, BigInt(betAmount)]);
        \\  await contract.deploy(provider, playerX, { satoshis: betAmount });
        \\  await contract.call('join', [playerOPub, null], provider, playerO, { satoshis: betAmount * 2 });
        \\  await contract.call('move', [0n, playerXPub, null], provider, playerX);
        \\  await contract.call('move', [3n, playerOPub, null], provider, playerO);
        \\  await contract.call('move', [1n, playerXPub, null], provider, playerX);
        \\  await contract.call('move', [4n, playerOPub, null], provider, playerO);
        \\  const xPkhHex = Utils.toHex(Hash.hash160(Utils.toArray(playerXPub, 'hex')));
        \\  const winnerP2PKH = '76a914' + xPkhHex + '88ac';
        \\  await contract.call(
        \\    'moveAndWin',
        \\    [2n, playerXPub, null, '00'.repeat(20), 0n],
        \\    provider,
        \\    playerX,
        \\    {
        \\      terminalOutputs: [
        \\        { scriptHex: winnerP2PKH, satoshis: betAmount * 2 },
        \\      ],
        \\    },
        \\  );
        \\  const txs = provider.getBroadcastedTxs();
        \\  process.stdout.write(JSON.stringify({
        \\    previous_tx_hex: txs[5],
        \\    call_tx_hex: txs[6],
        \\  }));
        \\})();
    ;

    const run_result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "node", "-e", code },
        .cwd = runar_root,
        .max_output_bytes = 2 * 1024 * 1024,
    }) catch |err| switch (err) {
        error.FileNotFound, error.CurrentWorkingDirectoryUnlinked => return error.SkipZigTest,
        else => return err,
    };
    defer allocator.free(run_result.stderr);
    defer allocator.free(run_result.stdout);

    switch (run_result.term) {
        .Exited => |code_value| {
            if (code_value != 0) {
                std.log.err("tic-tac-toe moveAndWin fixture build failed: {s}", .{run_result.stderr});
                return error.RunarCompileFailed;
            }
        },
        else => return error.RunarCompileFailed,
    }

    return std.json.parseFromSlice(DirectSpendFixtureJson, allocator, run_result.stdout, .{
        .allocate = .alloc_always,
    });
}

fn buildTicTacToeCancelFixture(allocator: std.mem.Allocator) !std.json.Parsed(DirectSpendFixtureJson) {
    const source_abs_rel = try std.fmt.allocPrint(allocator, "{s}/{s}", .{
        runar_root,
        "examples/ts/tic-tac-toe/TicTacToe.runar.ts",
    });
    defer allocator.free(source_abs_rel);
    try accessOrSkip(source_abs_rel);

    const sdk_abs_rel = try std.fmt.allocPrint(allocator, "{s}/{s}", .{
        runar_root,
        "packages/runar-sdk/dist/index.js",
    });
    defer allocator.free(sdk_abs_rel);
    try accessOrSkip(sdk_abs_rel);

    const code =
        \\(async () => {
        \\  const fs = require('fs');
        \\  const { compile } = await import('./packages/runar-compiler/dist/index.js');
        \\  const { RunarContract, MockProvider, LocalSigner } = await import('./packages/runar-sdk/dist/index.js');
        \\  const { Hash, Utils } = await import('@bsv/sdk');
        \\  const source = fs.readFileSync('examples/ts/tic-tac-toe/TicTacToe.runar.ts', 'utf-8');
        \\  const result = compile(source, { fileName: 'TicTacToe.runar.ts' });
        \\  if (!result.artifact) {
        \\    console.error(JSON.stringify(result));
        \\    process.exit(1);
        \\  }
        \\  const provider = new MockProvider();
        \\  const playerX = new LocalSigner('0000000000000000000000000000000000000000000000000000000000000003');
        \\  const playerO = new LocalSigner('0000000000000000000000000000000000000000000000000000000000000005');
        \\  const playerXPub = await playerX.getPublicKey();
        \\  const playerOPub = await playerO.getPublicKey();
        \\  const playerXAddr = await playerX.getAddress();
        \\  const playerOAddr = await playerO.getAddress();
        \\  provider.addUtxo(playerXAddr, {
        \\    txid: '23'.repeat(32),
        \\    outputIndex: 0,
        \\    satoshis: 500000,
        \\    script: '76a914' + '00'.repeat(20) + '88ac',
        \\  });
        \\  provider.addUtxo(playerOAddr, {
        \\    txid: '25'.repeat(32),
        \\    outputIndex: 0,
        \\    satoshis: 500000,
        \\    script: '76a914' + '00'.repeat(20) + '88ac',
        \\  });
        \\  const betAmount = 1000;
        \\  const contract = new RunarContract(result.artifact, [playerXPub, BigInt(betAmount)]);
        \\  contract.connect(provider, playerX);
        \\  await contract.deploy(provider, playerX, { satoshis: betAmount });
        \\  await contract.call('join', [playerOPub, null], provider, playerO, { satoshis: betAmount * 2 });
        \\  const xPkhHex = Utils.toHex(Hash.hash160(Utils.toArray(playerXPub, 'hex')));
        \\  const oPkhHex = Utils.toHex(Hash.hash160(Utils.toArray(playerOPub, 'hex')));
        \\  const prepared = await contract.prepareCall(
        \\    'cancel',
        \\    [null, null, '00'.repeat(20), 0n],
        \\    {
        \\      terminalOutputs: [
        \\        { scriptHex: '76a914' + xPkhHex + '88ac', satoshis: betAmount },
        \\        { scriptHex: '76a914' + oPkhHex + '88ac', satoshis: betAmount },
        \\      ],
        \\    },
        \\  );
        \\  const publicMethods = result.artifact.abi.methods.filter((method) => method.isPublic);
        \\  const methodIndex = publicMethods.findIndex((method) => method.name === 'cancel');
        \\  const sigSubscript = contract.getSubscriptForSigning(prepared._contractUtxo.script, methodIndex);
        \\  const txHex = prepared.tx.toHex();
        \\  const sigX = await playerX.sign(txHex, 0, sigSubscript, betAmount * 2);
        \\  const sigO = await playerO.sign(txHex, 0, sigSubscript, betAmount * 2);
        \\  await contract.finalizeCall(prepared, { 0: sigX, 1: sigO });
        \\  const txs = provider.getBroadcastedTxs();
        \\  process.stdout.write(JSON.stringify({
        \\    previous_tx_hex: txs[1],
        \\    call_tx_hex: txs[2],
        \\  }));
        \\})();
    ;

    const run_result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "node", "-e", code },
        .cwd = runar_root,
        .max_output_bytes = 2 * 1024 * 1024,
    }) catch |err| switch (err) {
        error.FileNotFound, error.CurrentWorkingDirectoryUnlinked => return error.SkipZigTest,
        else => return err,
    };
    defer allocator.free(run_result.stderr);
    defer allocator.free(run_result.stdout);

    switch (run_result.term) {
        .Exited => |code_value| {
            if (code_value != 0) {
                std.log.err("tic-tac-toe cancel fixture build failed: {s}", .{run_result.stderr});
                return error.RunarCompileFailed;
            }
        },
        else => return error.RunarCompileFailed,
    }

    return std.json.parseFromSlice(DirectSpendFixtureJson, allocator, run_result.stdout, .{
        .allocate = .alloc_always,
    });
}

fn buildFungibleTokenMergeFixture(allocator: std.mem.Allocator) !std.json.Parsed(MultiInputSpendFixtureJson) {
    const source_abs_rel = try std.fmt.allocPrint(allocator, "{s}/{s}", .{
        runar_root,
        "examples/ts/token-ft/FungibleTokenExample.runar.ts",
    });
    defer allocator.free(source_abs_rel);
    try accessOrSkip(source_abs_rel);

    const sdk_abs_rel = try std.fmt.allocPrint(allocator, "{s}/{s}", .{
        runar_root,
        "packages/runar-sdk/dist/index.js",
    });
    defer allocator.free(sdk_abs_rel);
    try accessOrSkip(sdk_abs_rel);

    const code =
        \\(async () => {
        \\  const fs = require('fs');
        \\  const { compile } = await import('./packages/runar-compiler/dist/index.js');
        \\  const { RunarContract, MockProvider, LocalSigner } = await import('./packages/runar-sdk/dist/index.js');
        \\  const source = fs.readFileSync('examples/ts/token-ft/FungibleTokenExample.runar.ts', 'utf-8');
        \\  const result = compile(source, { fileName: 'FungibleTokenExample.runar.ts' });
        \\  if (!result.artifact) {
        \\    console.error(JSON.stringify(result));
        \\    process.exit(1);
        \\  }
        \\  const provider = new MockProvider();
        \\  const signer = new LocalSigner('0000000000000000000000000000000000000000000000000000000000000001');
        \\  const address = await signer.getAddress();
        \\  const pubKeyHex = await signer.getPublicKey();
        \\  provider.addUtxo(address, {
        \\    txid: '36'.repeat(32),
        \\    outputIndex: 0,
        \\    satoshis: 1000000,
        \\    script: '76a914' + '00'.repeat(20) + '88ac',
        \\  });
        \\  const tokenIdHex = Buffer.from('FT-MERGE-LOCAL-001').toString('hex');
        \\  const contract1 = new RunarContract(result.artifact, [pubKeyHex, 400n, 0n, tokenIdHex]);
        \\  await contract1.deploy(provider, signer, { satoshis: 1 });
        \\  const contract2 = new RunarContract(result.artifact, [pubKeyHex, 600n, 0n, tokenIdHex]);
        \\  await contract2.deploy(provider, signer, { satoshis: 1 });
        \\  const utxo2 = contract2.getUtxo();
        \\  await contract1.call(
        \\    'merge',
        \\    [null, 600n, null, 1n],
        \\    provider,
        \\    signer,
        \\    {
        \\      additionalContractInputs: [utxo2],
        \\      additionalContractInputArgs: [[null, 400n, null, 1n]],
        \\      outputs: [
        \\        { satoshis: 1, state: { owner: pubKeyHex, balance: 400n, mergeBalance: 600n } },
        \\      ],
        \\    },
        \\  );
        \\  const txs = provider.getBroadcastedTxs();
        \\  process.stdout.write(JSON.stringify({
        \\    first_previous_tx_hex: txs[0],
        \\    second_previous_tx_hex: txs[1],
        \\    call_tx_hex: txs[2],
        \\  }));
        \\})();
    ;

    const run_result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "node", "-e", code },
        .cwd = runar_root,
        .max_output_bytes = 2 * 1024 * 1024,
    }) catch |err| switch (err) {
        error.FileNotFound, error.CurrentWorkingDirectoryUnlinked => return error.SkipZigTest,
        else => return err,
    };
    defer allocator.free(run_result.stderr);
    defer allocator.free(run_result.stdout);

    switch (run_result.term) {
        .Exited => |code_value| {
            if (code_value != 0) {
                std.log.err("fungible token merge fixture build failed: {s}", .{run_result.stderr});
                return error.RunarCompileFailed;
            }
        },
        else => return error.RunarCompileFailed,
    }

    return std.json.parseFromSlice(MultiInputSpendFixtureJson, allocator, run_result.stdout, .{
        .allocate = .alloc_always,
    });
}

fn verifyInputAgainstOutputOutcome(
    allocator: std.mem.Allocator,
    previous_tx_hex: []const u8,
    previous_output_index: usize,
    spend_tx_hex: []const u8,
    spend_input_index: usize,
) !harness.VerificationOutcome {
    const previous_tx_bytes = try bsvz.primitives.hex.decode(allocator, previous_tx_hex);
    defer allocator.free(previous_tx_bytes);
    var previous_tx = try Transaction.parse(allocator, previous_tx_bytes);
    defer previous_tx.deinit(allocator);

    const spend_tx_bytes = try bsvz.primitives.hex.decode(allocator, spend_tx_hex);
    defer allocator.free(spend_tx_bytes);
    var spend_tx = try Transaction.parse(allocator, spend_tx_bytes);
    defer spend_tx.deinit(allocator);

    const previous_output = previous_tx.outputs[previous_output_index];
    const unlocking_script = spend_tx.inputs[spend_input_index].unlocking_script;
    const locking_script = previous_output.locking_script;

    const exec_ctx = bsvz.script.context.ExecutionContext.forPrevoutSpend(
        allocator,
        &spend_tx,
        spend_input_index,
        previous_output,
    );
    return harness.verificationOutcomeDetailed(allocator, bsvz.script.thread.verifyExecutableScriptsDetailed(
        exec_ctx,
        Script.init(unlocking_script.bytes),
        locking_script,
    ));
}

fn verifyInputAgainstOutput(
    allocator: std.mem.Allocator,
    previous_tx_hex: []const u8,
    previous_output_index: usize,
    spend_tx_hex: []const u8,
    spend_input_index: usize,
) !bool {
    return switch (try verifyInputAgainstOutputOutcome(
        allocator,
        previous_tx_hex,
        previous_output_index,
        spend_tx_hex,
        spend_input_index,
    )) {
        .success => true,
        .eval_false => false,
        .script_error => |err| return err,
    };
}

fn verifyFirstInputAgainstFirstOutputOutcome(
    allocator: std.mem.Allocator,
    deploy_tx_hex: []const u8,
    call_tx_hex: []const u8,
) !harness.VerificationOutcome {
    return verifyInputAgainstOutputOutcome(allocator, deploy_tx_hex, 0, call_tx_hex, 0);
}

fn verifyFirstInputAgainstFirstOutput(
    allocator: std.mem.Allocator,
    deploy_tx_hex: []const u8,
    call_tx_hex: []const u8,
) !bool {
    return verifyInputAgainstOutput(allocator, deploy_tx_hex, 0, call_tx_hex, 0);
}

fn expectVerificationOutcome(
    actual: harness.VerificationOutcome,
    expected: harness.VerificationOutcome,
) !void {
    switch (expected) {
        .success => switch (actual) {
            .success => {},
            else => try std.testing.expect(false),
        },
        .eval_false => switch (actual) {
            .eval_false => {},
            else => try std.testing.expect(false),
        },
        .script_error => |want_err| switch (actual) {
            .script_error => |got_err| try std.testing.expectEqual(want_err, got_err),
            else => try std.testing.expect(false),
        },
    }
}

fn expectVerifySuccess(
    allocator: std.mem.Allocator,
    previous_tx_hex: []const u8,
    previous_output_index: usize,
    spend_tx_hex: []const u8,
    spend_input_index: usize,
) !void {
    try expectVerificationOutcome(
        try verifyInputAgainstOutputOutcome(
            allocator,
            previous_tx_hex,
            previous_output_index,
            spend_tx_hex,
            spend_input_index,
        ),
        .success,
    );
}

fn expectVerifyFalse(
    allocator: std.mem.Allocator,
    previous_tx_hex: []const u8,
    previous_output_index: usize,
    spend_tx_hex: []const u8,
    spend_input_index: usize,
) !void {
    try expectVerificationOutcome(
        try verifyInputAgainstOutputOutcome(
            allocator,
            previous_tx_hex,
            previous_output_index,
            spend_tx_hex,
            spend_input_index,
        ),
        .eval_false,
    );
}

fn expectVerifyError(
    allocator: std.mem.Allocator,
    previous_tx_hex: []const u8,
    previous_output_index: usize,
    spend_tx_hex: []const u8,
    spend_input_index: usize,
    want_err: bsvz.script.thread.Error,
) !void {
    try expectVerificationOutcome(
        try verifyInputAgainstOutputOutcome(
            allocator,
            previous_tx_hex,
            previous_output_index,
            spend_tx_hex,
            spend_input_index,
        ),
        .{ .script_error = want_err },
    );
}

fn expectFirstInputVerifySuccess(
    allocator: std.mem.Allocator,
    deploy_tx_hex: []const u8,
    call_tx_hex: []const u8,
) !void {
    try expectVerificationOutcome(
        try verifyFirstInputAgainstFirstOutputOutcome(allocator, deploy_tx_hex, call_tx_hex),
        .success,
    );
}

fn expectFirstInputVerifyFalse(
    allocator: std.mem.Allocator,
    deploy_tx_hex: []const u8,
    call_tx_hex: []const u8,
) !void {
    try expectVerificationOutcome(
        try verifyFirstInputAgainstFirstOutputOutcome(allocator, deploy_tx_hex, call_tx_hex),
        .eval_false,
    );
}

fn expectFirstInputVerifyError(
    allocator: std.mem.Allocator,
    deploy_tx_hex: []const u8,
    call_tx_hex: []const u8,
    want_err: bsvz.script.thread.Error,
) !void {
    try expectVerificationOutcome(
        try verifyFirstInputAgainstFirstOutputOutcome(allocator, deploy_tx_hex, call_tx_hex),
        .{ .script_error = want_err },
    );
}

test "local runar ec-primitives acceptance cases execute through bsvz when fixtures are present" {
    const allocator = std.testing.allocator;
    const locking_script_hex = try compileEcPrimitives(allocator);
    defer allocator.free(locking_script_hex);

    const two_g = Secp256k1.basePoint.dbl();
    const three_g = Secp256k1.basePoint.add(two_g);
    const seven_g = try Secp256k1.basePoint.mul(scalarBytes(7), .big);
    const forty_two_g = try Secp256k1.basePoint.mul(scalarBytes(42), .big);

    const two_g_hex = try pointHexAlloc(allocator, two_g);
    defer allocator.free(two_g_hex);

    const three_g_x_hex = try fieldHexAlloc(allocator, three_g.affineCoordinates().x);
    defer allocator.free(three_g_x_hex);
    const three_g_y_hex = try fieldHexAlloc(allocator, three_g.affineCoordinates().y);
    defer allocator.free(three_g_y_hex);

    const seven_g_x_hex = try fieldHexAlloc(allocator, seven_g.affineCoordinates().x);
    defer allocator.free(seven_g_x_hex);
    const seven_g_y_hex = try fieldHexAlloc(allocator, seven_g.affineCoordinates().y);
    defer allocator.free(seven_g_y_hex);

    const forty_two_g_x_hex = try fieldHexAlloc(allocator, forty_two_g.affineCoordinates().x);
    defer allocator.free(forty_two_g_x_hex);
    const forty_two_g_y_hex = try fieldHexAlloc(allocator, forty_two_g.affineCoordinates().y);
    defer allocator.free(forty_two_g_y_hex);

    const compressed_g_hex = try encodeHexAlloc(allocator, &Secp256k1.basePoint.toCompressedSec1());
    defer allocator.free(compressed_g_hex);

    const cases = [_]harness.Case{
        .{
            .name = "local runar ec checkX",
            .locking_script_hex = locking_script_hex,
            .args = &[_]harness.PushValue{.{ .script_num_hex = ec_gen_x_hex }},
            .method_selector = 0,
            .expect_success = true,
        },
        .{
            .name = "local runar ec checkY",
            .locking_script_hex = locking_script_hex,
            .args = &[_]harness.PushValue{.{ .script_num_hex = ec_gen_y_hex }},
            .method_selector = 1,
            .expect_success = true,
        },
        .{
            .name = "local runar ec checkOnCurve",
            .locking_script_hex = locking_script_hex,
            .args = &[_]harness.PushValue{},
            .method_selector = 2,
            .expect_success = true,
        },
        .{
            .name = "local runar ec checkNegateY",
            .locking_script_hex = locking_script_hex,
            .args = &[_]harness.PushValue{.{ .script_num_hex = ec_neg_y_hex }},
            .method_selector = 3,
            .expect_success = true,
        },
        .{
            .name = "local runar ec checkModReduce",
            .locking_script_hex = locking_script_hex,
            .args = &[_]harness.PushValue{
                .{ .int = -7 },
                .{ .int = 5 },
                .{ .int = 3 },
            },
            .method_selector = 4,
            .expect_success = true,
        },
        .{
            .name = "local runar ec checkAdd",
            .locking_script_hex = locking_script_hex,
            .args = &[_]harness.PushValue{
                .{ .hex = two_g_hex },
                .{ .script_num_hex = three_g_x_hex },
                .{ .script_num_hex = three_g_y_hex },
            },
            .method_selector = 5,
            .expect_success = true,
        },
        .{
            .name = "local runar ec checkMul",
            .locking_script_hex = locking_script_hex,
            .args = &[_]harness.PushValue{
                .{ .int = 7 },
                .{ .script_num_hex = seven_g_x_hex },
                .{ .script_num_hex = seven_g_y_hex },
            },
            .method_selector = 6,
            .expect_success = true,
        },
        .{
            .name = "local runar ec checkMulGen",
            .locking_script_hex = locking_script_hex,
            .args = &[_]harness.PushValue{
                .{ .int = 42 },
                .{ .script_num_hex = forty_two_g_x_hex },
                .{ .script_num_hex = forty_two_g_y_hex },
            },
            .method_selector = 7,
            .expect_success = true,
        },
        .{
            .name = "local runar ec checkMakePoint",
            .locking_script_hex = locking_script_hex,
            .args = &[_]harness.PushValue{
                .{ .script_num_hex = ec_gen_x_hex },
                .{ .script_num_hex = ec_gen_y_hex },
                .{ .script_num_hex = ec_gen_x_hex },
                .{ .script_num_hex = ec_gen_y_hex },
            },
            .method_selector = 8,
            .expect_success = true,
        },
        .{
            .name = "local runar ec checkEncodeCompressed",
            .locking_script_hex = locking_script_hex,
            .args = &[_]harness.PushValue{.{ .hex = compressed_g_hex }},
            .method_selector = 9,
            .expect_success = true,
        },
        .{
            .name = "local runar ec checkMulIdentity",
            .locking_script_hex = locking_script_hex,
            .args = &[_]harness.PushValue{},
            .method_selector = 10,
            .expect_success = true,
        },
        .{
            .name = "local runar ec checkNegateRoundtrip",
            .locking_script_hex = locking_script_hex,
            .args = &[_]harness.PushValue{},
            .method_selector = 11,
            .expect_success = true,
        },
        .{
            .name = "local runar ec checkAddOnCurve",
            .locking_script_hex = locking_script_hex,
            .args = &[_]harness.PushValue{.{ .hex = two_g_hex }},
            .method_selector = 12,
            .expect_success = true,
        },
        .{
            .name = "local runar ec checkMulGenOnCurve",
            .locking_script_hex = locking_script_hex,
            .args = &[_]harness.PushValue{.{ .int = 42 }},
            .method_selector = 13,
            .expect_success = true,
        },
    };

    for (cases) |case| {
        const actual = harness.runCase(allocator, case) catch |err| {
            std.log.err("local runar acceptance case failed: {s}", .{case.name});
            return err;
        };
        try std.testing.expectEqual(case.expect_success, actual);
    }
}

test "local runar convergence-proof acceptance executes through bsvz when fixtures are present" {
    const allocator = std.testing.allocator;

    const r_a = try Secp256k1.basePoint.mul(scalarBytes(14), .big);
    const r_b = try Secp256k1.basePoint.mul(scalarBytes(9), .big);

    const r_a_hex = try pointHexAlloc(allocator, r_a);
    defer allocator.free(r_a_hex);
    const r_b_hex = try pointHexAlloc(allocator, r_b);
    defer allocator.free(r_b_hex);

    const args_json = try std.fmt.allocPrint(allocator, "{{\"rA\":\"{s}\",\"rB\":\"{s}\"}}", .{
        r_a_hex,
        r_b_hex,
    });
    defer allocator.free(args_json);

    const locking_script_hex = try compileRunarContract(
        allocator,
        "conformance/tests/convergence-proof/convergence-proof.runar.ts",
        "convergence-proof.runar.ts",
        args_json,
    );
    defer allocator.free(locking_script_hex);

    const actual = try harness.runCase(allocator, .{
        .name = "local runar convergence proof",
        .locking_script_hex = locking_script_hex,
        .args = &[_]harness.PushValue{.{ .int = 5 }},
        .expect_success = true,
    });
    try std.testing.expect(actual);
}

test "local runar stateful-counter increment spend verifies through bsvz" {
    const allocator = std.testing.allocator;
    const fixture = try buildStatefulCounterFixture(allocator);
    defer fixture.deinit();

    try std.testing.expect(try verifyFirstInputAgainstFirstOutput(
        allocator,
        fixture.value.deploy_tx_hex,
        fixture.value.call_tx_hex,
    ));
}

test "local runar stateful signed reset spend verifies through bsvz" {
    const allocator = std.testing.allocator;
    const fixture = try buildStatefulSignedCounterFixture(allocator);
    defer fixture.deinit();

    try std.testing.expect(try verifyFirstInputAgainstFirstOutput(
        allocator,
        fixture.value.deploy_tx_hex,
        fixture.value.call_tx_hex,
    ));
}

test "local runar covenant vault spend verifies through bsvz" {
    const allocator = std.testing.allocator;
    const fixture = try buildCovenantVaultFixture(allocator);
    defer fixture.deinit();

    try std.testing.expect(try verifyFirstInputAgainstFirstOutput(
        allocator,
        fixture.value.deploy_tx_hex,
        fixture.value.call_tx_hex,
    ));
}

test "local runar covenant vault wrong payout amount fails through bsvz" {
    const allocator = std.testing.allocator;
    const fixture = try buildCovenantVaultWrongAmountFixture(allocator);
    defer fixture.deinit();

    try expectFirstInputVerifyFalse(
        allocator,
        fixture.value.deploy_tx_hex,
        fixture.value.call_tx_hex,
    );
}

test "local runar auction bid spend verifies through bsvz" {
    const allocator = std.testing.allocator;
    const fixture = try buildAuctionBidFixture(allocator);
    defer fixture.deinit();

    try std.testing.expect(try verifyFirstInputAgainstFirstOutput(
        allocator,
        fixture.value.deploy_tx_hex,
        fixture.value.call_tx_hex,
    ));
}

test "local runar auction close after deadline verifies through bsvz" {
    const allocator = std.testing.allocator;
    const fixture = try buildAuctionCloseFixture(allocator, 0);
    defer fixture.deinit();

    try std.testing.expect(try verifyFirstInputAgainstFirstOutput(
        allocator,
        fixture.value.deploy_tx_hex,
        fixture.value.call_tx_hex,
    ));
}

test "local runar auction close before deadline fails through bsvz" {
    const allocator = std.testing.allocator;
    const fixture = try buildAuctionCloseFixture(allocator, 1);
    defer fixture.deinit();

    try expectFirstInputVerifyFalse(
        allocator,
        fixture.value.deploy_tx_hex,
        fixture.value.call_tx_hex,
    );
}

test "local runar auction sequential bids verify through bsvz" {
    const allocator = std.testing.allocator;
    const fixture = try buildAuctionTwoBidFixture(allocator);
    defer fixture.deinit();

    try std.testing.expect(try verifyInputAgainstOutput(
        allocator,
        fixture.value.deploy_tx_hex,
        0,
        fixture.value.first_call_tx_hex,
        0,
    ));

    try std.testing.expect(try verifyInputAgainstOutput(
        allocator,
        fixture.value.first_call_tx_hex,
        0,
        fixture.value.second_call_tx_hex,
        0,
    ));
}

test "local runar nft transfer and burn verify through bsvz" {
    const allocator = std.testing.allocator;
    const fixture = try buildNftTransferBurnFixture(allocator);
    defer fixture.deinit();

    try std.testing.expect(try verifyInputAgainstOutput(
        allocator,
        fixture.value.deploy_tx_hex,
        0,
        fixture.value.first_call_tx_hex,
        0,
    ));

    try std.testing.expect(try verifyInputAgainstOutput(
        allocator,
        fixture.value.first_call_tx_hex,
        0,
        fixture.value.second_call_tx_hex,
        0,
    ));
}

test "local runar math-demo exponentiate then log2 verifies through bsvz" {
    const allocator = std.testing.allocator;
    const fixture = try buildMathDemoExponentiateLog2Fixture(allocator);
    defer fixture.deinit();

    try std.testing.expect(try verifyInputAgainstOutput(
        allocator,
        fixture.value.deploy_tx_hex,
        0,
        fixture.value.first_call_tx_hex,
        0,
    ));

    try std.testing.expect(try verifyInputAgainstOutput(
        allocator,
        fixture.value.first_call_tx_hex,
        0,
        fixture.value.second_call_tx_hex,
        0,
    ));
}

test "local runar sha256 compress verifies through bsvz" {
    const allocator = std.testing.allocator;
    const fixture = try buildSha256CompressFixture(allocator);
    defer fixture.deinit();

    try std.testing.expect(try verifyFirstInputAgainstFirstOutput(
        allocator,
        fixture.value.deploy_tx_hex,
        fixture.value.call_tx_hex,
    ));
}

test "local runar fungible token transfer verifies through bsvz" {
    const allocator = std.testing.allocator;
    const fixture = try buildFungibleTokenTransferFixture(allocator);
    defer fixture.deinit();

    try std.testing.expect(try verifyFirstInputAgainstFirstOutput(
        allocator,
        fixture.value.deploy_tx_hex,
        fixture.value.call_tx_hex,
    ));
}

test "local runar escrow release verifies through bsvz" {
    const allocator = std.testing.allocator;
    const fixture = try buildEscrowFixture(
        allocator,
        "release",
        "0000000000000000000000000000000000000000000000000000000000000002",
        "0000000000000000000000000000000000000000000000000000000000000003",
        "3131313131313131313131313131313131313131313131313131313131313131",
    );
    defer fixture.deinit();

    try std.testing.expect(try verifyFirstInputAgainstFirstOutput(
        allocator,
        fixture.value.deploy_tx_hex,
        fixture.value.call_tx_hex,
    ));
}

test "local runar escrow refund verifies through bsvz" {
    const allocator = std.testing.allocator;
    const fixture = try buildEscrowFixture(
        allocator,
        "refund",
        "0000000000000000000000000000000000000000000000000000000000000001",
        "0000000000000000000000000000000000000000000000000000000000000003",
        "3232323232323232323232323232323232323232323232323232323232323232",
    );
    defer fixture.deinit();

    try std.testing.expect(try verifyFirstInputAgainstFirstOutput(
        allocator,
        fixture.value.deploy_tx_hex,
        fixture.value.call_tx_hex,
    ));
}

test "local runar tic-tac-toe moveAndWin verifies through bsvz" {
    const allocator = std.testing.allocator;
    const fixture = try buildTicTacToeMoveAndWinFixture(allocator);
    defer fixture.deinit();

    try std.testing.expect(try verifyInputAgainstOutput(
        allocator,
        fixture.value.previous_tx_hex,
        0,
        fixture.value.call_tx_hex,
        0,
    ));
}

test "local runar tic-tac-toe cancel verifies through bsvz" {
    const allocator = std.testing.allocator;
    const fixture = try buildTicTacToeCancelFixture(allocator);
    defer fixture.deinit();

    try std.testing.expect(try verifyInputAgainstOutput(
        allocator,
        fixture.value.previous_tx_hex,
        0,
        fixture.value.call_tx_hex,
        0,
    ));
}

test "local runar fungible token merge verifies both contract inputs through bsvz" {
    const allocator = std.testing.allocator;
    const fixture = try buildFungibleTokenMergeFixture(allocator);
    defer fixture.deinit();

    try std.testing.expect(try verifyInputAgainstOutput(
        allocator,
        fixture.value.first_previous_tx_hex,
        0,
        fixture.value.call_tx_hex,
        0,
    ));

    try std.testing.expect(try verifyInputAgainstOutput(
        allocator,
        fixture.value.second_previous_tx_hex,
        0,
        fixture.value.call_tx_hex,
        1,
    ));
}

test "local runar sha256 finalize cross-verifies abc through bsvz" {
    const allocator = std.testing.allocator;
    const source =
        \\import { SmartContract, assert, sha256Finalize, sha256 } from 'runar-lang';
        \\import type { ByteString } from 'runar-lang';
        \\
        \\class Sha256FinalizeCross extends SmartContract {
        \\  readonly initState: ByteString;
        \\
        \\  constructor(initState: ByteString) {
        \\    super(initState);
        \\    this.initState = initState;
        \\  }
        \\
        \\  public verify(message: ByteString, msgBitLen: bigint) {
        \\    const computed = sha256Finalize(this.initState, message, msgBitLen);
        \\    const native = sha256(message);
        \\    assert(computed === native);
        \\  }
        \\}
    ;

    const args_json = try std.fmt.allocPrint(allocator, "{{\"initState\":\"{s}\"}}", .{sha256_init_hex});
    defer allocator.free(args_json);

    const locking_script_hex = try compileInlineRunarContract(
        allocator,
        source,
        "Sha256FinalizeCross.runar.ts",
        args_json,
    );
    defer allocator.free(locking_script_hex);

    const actual = try harness.runCase(allocator, .{
        .name = "local runar sha256 finalize abc",
        .locking_script_hex = locking_script_hex,
        .args = &[_]harness.PushValue{
            .{ .hex = "616263" },
            .{ .int = 24 },
        },
        .expect_success = true,
    });
    try std.testing.expect(actual);
}

test "local runar sha256 finalize chained 120-byte message verifies through bsvz" {
    const allocator = std.testing.allocator;
    const source =
        \\import { SmartContract, assert, sha256Compress, sha256Finalize, sha256 } from 'runar-lang';
        \\import type { ByteString } from 'runar-lang';
        \\
        \\class Sha256FinalizeChained extends SmartContract {
        \\  readonly initState: ByteString;
        \\
        \\  constructor(initState: ByteString) {
        \\    super(initState);
        \\    this.initState = initState;
        \\  }
        \\
        \\  public verify(message: ByteString, firstBlock: ByteString, remaining: ByteString, totalBitLen: bigint) {
        \\    const mid = sha256Compress(this.initState, firstBlock);
        \\    const computed = sha256Finalize(mid, remaining, totalBitLen);
        \\    const native = sha256(message);
        \\    assert(computed === native);
        \\  }
        \\}
    ;

    const args_json = try std.fmt.allocPrint(allocator, "{{\"initState\":\"{s}\"}}", .{sha256_init_hex});
    defer allocator.free(args_json);

    const locking_script_hex = try compileInlineRunarContract(
        allocator,
        source,
        "Sha256FinalizeChained.runar.ts",
        args_json,
    );
    defer allocator.free(locking_script_hex);

    const full_message_hex = "ee" ** 120;
    const first_block_hex = full_message_hex[0..128];
    const remaining_hex = full_message_hex[128..];

    const actual = try harness.runCase(allocator, .{
        .name = "local runar sha256 finalize chained 120-byte",
        .locking_script_hex = locking_script_hex,
        .args = &[_]harness.PushValue{
            .{ .hex = full_message_hex },
            .{ .hex = first_block_hex },
            .{ .hex = remaining_hex },
            .{ .int = 960 },
        },
        .expect_success = true,
    });
    try std.testing.expect(actual);
}

test "local runar blake3 hash abc verifies through bsvz" {
    const allocator = std.testing.allocator;
    const source =
        \\import { SmartContract, assert, blake3Hash } from 'runar-lang';
        \\import type { ByteString } from 'runar-lang';
        \\
        \\class Blake3HashSingle extends SmartContract {
        \\  readonly expected: ByteString;
        \\
        \\  constructor(expected: ByteString) {
        \\    super(expected);
        \\    this.expected = expected;
        \\  }
        \\
        \\  public verify(message: ByteString) {
        \\    const result = blake3Hash(message);
        \\    assert(result === this.expected);
        \\  }
        \\}
    ;

    const args_json = try std.fmt.allocPrint(allocator, "{{\"expected\":\"{s}\"}}", .{blake3_hash_abc_hex});
    defer allocator.free(args_json);

    const locking_script_hex = try compileInlineRunarContract(
        allocator,
        source,
        "Blake3HashSingle.runar.ts",
        args_json,
    );
    defer allocator.free(locking_script_hex);

    const actual = try harness.runCase(allocator, .{
        .name = "local runar blake3 hash abc",
        .locking_script_hex = locking_script_hex,
        .args = &[_]harness.PushValue{.{ .hex = "616263" }},
        .expect_success = true,
    });
    try std.testing.expect(actual);
}

test "local runar p2blake3pkh verifies the matching key through bsvz" {
    const allocator = std.testing.allocator;
    const args_json = try std.fmt.allocPrint(allocator, "{{\"pubKeyHash\":\"{s}\"}}", .{key_one_blake3_hash_hex});
    defer allocator.free(args_json);

    const locking_script_hex = try compileRunarContract(
        allocator,
        "examples/ts/p2blake3pkh/P2Blake3PKH.runar.ts",
        "P2Blake3PKH.runar.ts",
        args_json,
    );
    defer allocator.free(locking_script_hex);

    const actual = try harness.runCase(allocator, .{
        .name = "local runar p2blake3pkh success",
        .locking_script_hex = locking_script_hex,
        .args = &[_]harness.PushValue{
            .{ .signature = {} },
            .{ .hex = key_one_pub_hex },
        },
        .expect_success = true,
        .spend = .{ .signing_key = [_]u8{0} ** 31 ++ [_]u8{1} },
    });
    try std.testing.expect(actual);
}

test "local runar p2blake3pkh rejects the wrong pubkey through bsvz" {
    const allocator = std.testing.allocator;
    const args_json = try std.fmt.allocPrint(allocator, "{{\"pubKeyHash\":\"{s}\"}}", .{key_one_blake3_hash_hex});
    defer allocator.free(args_json);

    const locking_script_hex = try compileRunarContract(
        allocator,
        "examples/ts/p2blake3pkh/P2Blake3PKH.runar.ts",
        "P2Blake3PKH.runar.ts",
        args_json,
    );
    defer allocator.free(locking_script_hex);

    const actual = try harness.runCase(allocator, .{
        .name = "local runar p2blake3pkh wrong pubkey",
        .locking_script_hex = locking_script_hex,
        .args = &[_]harness.PushValue{
            .{ .signature = {} },
            .{ .hex = key_two_pub_hex },
        },
        .expect_success = false,
        .spend = .{ .signing_key = [_]u8{0} ** 31 ++ [_]u8{2} },
    });
    try std.testing.expect(!actual);
}
