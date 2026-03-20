# SPV and Broadcast

## SPV verification

For transaction graphs already hydrated with source transactions or source outputs:

```zig
const ok = try bsvz.spv.verify(
    allocator,
    &tx,
    bsvz.spv.GullibleChainTracker{},
    null,
);
```

`GullibleChainTracker` accepts every Merkle root. Replace it with your own chain tracker when you want header-backed root validation.

## BEEF verification

```zig
var beef = try bsvz.transaction.newBeefFromHex(allocator, beef_hex);
defer beef.deinit();

const ok = try bsvz.spv.verifyBeef(
    allocator,
    &beef,
    root_txid,
    bsvz.spv.GullibleChainTracker{},
    null,
);
```

## MerklePath

Relevant `bsvz.spv.MerklePath` helpers include:

- `parse(...)`
- `bytes(...)`
- `computeRoot(...)`
- `combine(...)`
- `verify(...)`
- `findLeafByOffset(...)`
- `addLeaf(...)`

## Broadcast clients

Available clients:

- `bsvz.broadcast.woc.WhatsOnChain`
- `bsvz.broadcast.taal.Taal`
- `bsvz.broadcast.arc.Arc`

ARC is generic. GorillaPool is just an ARC base URL:

```zig
const broadcaster = bsvz.broadcast.arc.Arc{
    .api_url = "https://arc.gorillapool.io",
};

var result = try broadcaster.broadcast(allocator, &tx);
defer result.deinit(allocator);
```

You can also query ARC status with:

- `bsvz.broadcast.arc.Arc.status(...)`

Runnable example:

- [../../examples/gorillapool_arc_demo.zig](../../examples/gorillapool_arc_demo.zig)
