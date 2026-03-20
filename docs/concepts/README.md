# Concepts

## Ownership

Public parse/build APIs in `bsvz` return owned values. If a type exposes `deinit(allocator)`, call it when you are done.

The main owned types are:

- `transaction.Transaction`
- `transaction.Beef`
- `spv.MerklePath`
- `broadcast.BroadcastResult`

## Script execution model

There are two layers:

- `bsvz.script.thread`
  - reusable, lower-level, explicit execution surface
- `bsvz.script.interpreter`
  - smaller wrappers for common verification tasks

Use the thread API when you want reuse, tracing, or more control over execution. Use the interpreter wrappers for straightforward prevout verification.

## Transaction ancestry

Inputs can carry:

- `source_output`
- `source_transaction`

That lets fee calculation, EF/BEEF serialization, script verification, and SPV traversal operate without rebuilding ancestry out-of-band.

## BEEF and SPV

`bsvz.transaction.beef` owns parsed transactions and proof structures. `bsvz.spv.verifyBeef(...)` walks that container and verifies ancestor spends and Merkle roots from the chosen root transaction.
