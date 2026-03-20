# Script Verification

`bsvz` exposes both a reusable thread API and smaller interpreter wrappers.

## Plain script pair

```zig
var thread = bsvz.script.thread.ScriptThread.init(.{ .allocator = allocator });
defer thread.deinit();

const ok = try thread.verifyPair(
    bsvz.script.Script.init(unlocking_bytes),
    bsvz.script.Script.init(locking_bytes),
);
```

## Prevout spend verification

Use this when `CHECKSIG` / `CHECKMULTISIG` need transaction context:

```zig
const ok = try bsvz.script.interpreter.verifyPrevout(.{
    .allocator = allocator,
    .tx = &spend_tx,
    .input_index = 0,
    .previous_output = source_output,
    .unlocking_script = spend_tx.inputs[0].unlocking_script,
});
```

Detailed and traced variants:

- `verifyDetailed(...)`
- `verifyTraced(...)`
- `verifyPrevoutDetailed(...)`
- `verifyPrevoutTraced(...)`

## Legacy P2SH behavior

If you need historical legacy-P2SH execution semantics, use the explicit legacy-P2SH entry points on `bsvz.script.thread`.

## Trace output

The traced results expose a `writeDebug(...)` helper:

```zig
var traced = bsvz.script.thread.verifyScriptsTraced(
    .{ .allocator = allocator },
    bsvz.script.Script.init(unlocking_bytes),
    bsvz.script.Script.init(locking_bytes),
);
defer traced.deinit(allocator);

try traced.writeDebug(std.io.getStdOut().writer());
```

Runnable examples:

- [../../examples/script_trace_demo.zig](../../examples/script_trace_demo.zig)
- [../../examples/prevout_trace_demo.zig](../../examples/prevout_trace_demo.zig)
