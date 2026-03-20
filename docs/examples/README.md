# Examples & Usage Guides

These guides cover the main `bsvz` workflows in the same spirit as the Go SDK examples, but with fewer pages and more direct snippets.

## Transactions

- [Transactions](./transactions.md)
  - parse and serialize raw hex
  - build and sign P2PKH transactions
  - add change and apply fees
  - parse and extract BEEF payloads

## Keys, addresses, and messages

- [Keys and Messages](./keys-and-messages.md)
  - WIF and address conversion
  - BIP32/BIP39
  - Type-42 / ECDH
  - BRC-77 signed messages
  - BRC-78 encrypted messages

## Script, SPV, and broadcast

- [Script Verification](./script-verification.md)
  - plain script pairs
  - prevout spend verification
  - traced execution
- [SPV and Broadcast](./spv-and-broadcast.md)
  - MerklePath and BEEF verification
  - WhatsOnChain / TAAL / ARC broadcast
  - GorillaPool ARC usage

## Runnable code examples

- [../../examples/hash_demo.zig](../../examples/hash_demo.zig)
- [../../examples/script_trace_demo.zig](../../examples/script_trace_demo.zig)
- [../../examples/prevout_trace_demo.zig](../../examples/prevout_trace_demo.zig)
- [../../examples/gorillapool_arc_demo.zig](../../examples/gorillapool_arc_demo.zig)
