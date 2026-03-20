# Script templates

TypeScript counterparts live in **[bsv-blockchain/ts-templates](https://github.com/bsv-blockchain/ts-templates/tree/master/src)** (`OpReturn.ts`, `MultiPushDrop.ts`, `P2MSKH.ts`). The main SDK also ships templates (e.g. PushDrop, P2PKH, RPuzzle) under `@bsv/sdk`; this table maps those sources to `bsvz`.

| Upstream | bsvz module |
|----------|-------------|
| [OpReturn.ts](https://github.com/bsv-blockchain/ts-templates/blob/master/src/OpReturn.ts) | `op_return.zig` — use `encodeWithFalsePrelude` for the same `OP_0` + `OP_RETURN` + push layout as ts-templates |
| [MultiPushDrop.ts](https://github.com/bsv-blockchain/ts-templates/blob/master/src/MultiPushDrop.ts) | `multi_pushdrop.zig` — reference link only; 1-of-N + fields not ported |
| [P2MSKH.ts](https://github.com/bsv-blockchain/ts-templates/blob/master/src/P2MSKH.ts) | `p2mskh.zig` — reference link only; wallet-backed multisig lock not ported |
| PushDrop (SDK) | `pushdrop.zig` |
| P2PKH (SDK) | `p2pkh.zig` |
| RPuzzle (SDK) | `r_puzzle.zig` |
