//! BRC-21 Push TX — preimage + `OP_CHECKSIG` covenants; not a single fixed locking script.
//! See https://bsv.brc.dev/scripts/0021 and nChain WP-1605.
//!
//! Common shortcut: sign with `k = 1` private key so verifiers use a well-known pubkey (generator).
pub const privkey_one_hex =
    "0000000000000000000000000000000000000000000000000000000000000001";

pub const brc_url = "https://bsv.brc.dev/scripts/0021";
