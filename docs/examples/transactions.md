# Transactions

## Parse and serialize

```zig
const tx_hex = "010000000100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff010100000000000000015100000000";

var tx = try bsvz.transaction.Transaction.parseHex(allocator, tx_hex);
defer tx.deinit(allocator);

const encoded = try tx.hex(allocator);
defer allocator.free(encoded);

const extended = try tx.extendedHex(allocator);
defer allocator.free(extended);
```

## Build and sign a P2PKH transaction

`bsvz.transaction.Builder` owns cloned inputs and outputs. Build a transaction, apply fees, then sign:

```zig
var builder = bsvz.transaction.Builder.init(allocator);
defer builder.deinit();

try builder.addInputFromTx(&source_tx, 0);
try builder.payToAddress("1AdZmoAQUw4XCsCihukoHMvNWXcsd8jDN6", 1_000);
try builder.addChangeOutputToAddress("1AdZmoAQUw4XCsCihukoHMvNWXcsd8jDN6");

const fee_model = bsvz.transaction.fee_model.SatoshisPerKilobyte{ .value = 10 };
try builder.applyFee(fee_model, .equal);
try builder.sign(private_key);

var tx = try builder.build();
defer tx.deinit(allocator);
```

If you want the builder to do both fee application and signing, use:

- `finalizeSigned(...)`
- `finalizeSignedAllP2pkh(...)`

## Fee helpers

The transaction surface also exposes totals and fee wrappers:

- `tx.totalInputSatoshis()`
- `tx.totalOutputSatoshis()`
- `tx.getFee()`
- `tx.applyFee(...)`

## BEEF

Parse BEEF from bytes or hex:

```zig
var beef = try bsvz.transaction.newBeefFromHex(allocator, beef_hex);
defer beef.deinit();

const root_txid = try txid_hash_from_hex();
const tx = beef.findTransaction(root_txid) orelse return error.MissingTransaction;
```

Extract the subject transaction directly:

```zig
var tx = try bsvz.transaction.newTransactionFromBeefHex(allocator, beef_hex);
defer tx.deinit(allocator);
```

Relevant entry points:

- `bsvz.transaction.Transaction`
- `bsvz.transaction.Builder`
- `bsvz.transaction.newBeefFromHex`
- `bsvz.transaction.newBeefFromBytes`
- `bsvz.transaction.newTransactionFromBeef`
- `bsvz.transaction.newTransactionFromBeefHex`
