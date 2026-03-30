//! C ABI exports for bsvz — allows linking libbsvz.a into C/C++ projects.
//! All functions return 0 on success, negative on failure.
//! Allocations use page_allocator since callers cannot provide a Zig allocator.

const std = @import("std");
const bsvz = @import("bsvz");
const bip39 = bsvz.primitives.bip39;
const bip32 = bsvz.primitives.bip32;
const brc43 = bsvz.primitives.brc43;
const ec = bsvz.primitives.ec;
const crypto = bsvz.crypto;
const compat_wif = bsvz.compat.wif;
const compat_address = bsvz.compat.address;
const compat_bsm = bsvz.compat.bsm;
const msg_signed = bsvz.message.signed;

const alloc = std.heap.page_allocator;

// Error codes
const OK: c_int = 0;
const ERR_INVALID_INPUT: c_int = -1;
const ERR_CRYPTO: c_int = -2;
const ERR_BUFFER_TOO_SMALL: c_int = -3;
const ERR_ALLOC: c_int = -4;
const ERR_INTERNAL: c_int = -5;

fn copyToOut(src: []const u8, out_buf: [*c]u8, out_len: *usize) c_int {
    @memcpy(out_buf[0..src.len], src);
    out_len.* = src.len;
    return OK;
}

// ── BIP39 ───────────────────────────────────────────────────────────────

/// Generate a BIP39 mnemonic. entropy_bits must be 128, 160, 192, 224, or 256.
/// out_buf must be at least 256 bytes. out_len receives actual length.
export fn bsvz_mnemonic_generate(entropy_bits: c_int, out_buf: [*c]u8, out_len: *usize) c_int {
    const bits: usize = @intCast(entropy_bits);
    const entropy = bip39.newEntropy(alloc, bits) catch return ERR_INVALID_INPUT;
    defer alloc.free(entropy);
    const mnemonic = bip39.newMnemonic(alloc, entropy) catch return ERR_CRYPTO;
    defer alloc.free(mnemonic);
    return copyToOut(mnemonic, out_buf, out_len);
}

/// Derive a 64-byte seed from a mnemonic + passphrase (BIP39 PBKDF2).
/// out_seed must be at least 64 bytes.
export fn bsvz_mnemonic_to_seed(
    mnemonic_ptr: [*c]const u8,
    mnemonic_len: usize,
    passphrase_ptr: [*c]const u8,
    pass_len: usize,
    out_seed: [*c]u8,
) c_int {
    const mnemonic = mnemonic_ptr[0..mnemonic_len];
    const passphrase = passphrase_ptr[0..pass_len];
    const seed = bip39.newSeed(alloc, mnemonic, passphrase) catch return ERR_CRYPTO;
    @memcpy(out_seed[0..64], &seed);
    return OK;
}

// ── BIP32 ───────────────────────────────────────────────────────────────

/// Create a master HD key from a seed. out_key receives the base58-serialized xprv.
/// out_key must be at least 120 bytes. out_key_len receives actual length.
export fn bsvz_hd_from_seed(
    seed_ptr: [*c]const u8,
    seed_len: usize,
    out_key: [*c]u8,
    out_key_len: *usize,
) c_int {
    if (seed_len < bip32.min_seed_len or seed_len > bip32.max_seed_len) return ERR_INVALID_INPUT;
    const seed = seed_ptr[0..seed_len];
    const master = bip32.newMaster(seed, bip32.Versions.mainnet) catch return ERR_CRYPTO;
    const serialized = master.toStringAlloc(alloc) catch return ERR_ALLOC;
    defer alloc.free(serialized);
    return copyToOut(serialized, out_key, out_key_len);
}

/// Derive a child key from a base58 xprv/xpub using a BIP32 path like "m/44'/236'/0'/0/0".
/// The "m/" prefix is optional and stripped. out_key receives base58-serialized result.
/// out_key must be at least 120 bytes.
export fn bsvz_hd_derive_path(
    key_ptr: [*c]const u8,
    key_len: usize,
    path_ptr: [*c]const u8,
    path_len: usize,
    out_key: [*c]u8,
    out_key_len: *usize,
) c_int {
    const key_str = key_ptr[0..key_len];
    const parent = bip32.parseAlloc(alloc, key_str) catch return ERR_INVALID_INPUT;
    var path = path_ptr[0..path_len];
    // Strip "m/" prefix if present
    if (path.len >= 2 and path[0] == 'm' and path[1] == '/') {
        path = path[2..];
    } else if (path.len == 1 and path[0] == 'm') {
        const serialized = parent.toStringAlloc(alloc) catch return ERR_ALLOC;
        defer alloc.free(serialized);
        return copyToOut(serialized, out_key, out_key_len);
    }
    const derived = parent.derivePath(path) catch return ERR_CRYPTO;
    const serialized = derived.toStringAlloc(alloc) catch return ERR_ALLOC;
    defer alloc.free(serialized);
    return copyToOut(serialized, out_key, out_key_len);
}

/// Extract the raw 32-byte private key from an xprv (base58-serialized).
/// out_privkey must be at least 32 bytes.
export fn bsvz_hd_privkey_bytes(
    key_ptr: [*c]const u8,
    key_len: usize,
    out_privkey: [*c]u8,
) c_int {
    const key_str = key_ptr[0..key_len];
    const ext = bip32.parseAlloc(alloc, key_str) catch return ERR_INVALID_INPUT;
    switch (ext.payload) {
        .private => |k| {
            @memcpy(out_privkey[0..32], &k);
            return OK;
        },
        .public => return ERR_INVALID_INPUT,
    }
}

// ── Type-42 / BRC-42 / BRC-43 ──────────────────────────────────────────

/// BRC-43: Format an invoice number from (security_level, protocol_id, key_id).
/// Returns the invoice string like "2-message signing-abc123".
/// out_buf must be at least 1300 bytes. out_len receives actual length.
export fn bsvz_brc43_invoice(
    security_level: u8,
    protocol_ptr: [*c]const u8,
    protocol_len: usize,
    key_id_ptr: [*c]const u8,
    key_id_len: usize,
    out_buf: [*c]u8,
    out_len: *usize,
) c_int {
    const protocol = protocol_ptr[0..protocol_len];
    const key_id = key_id_ptr[0..key_id_len];
    const invoice = brc43.formatInvoice(alloc, security_level, protocol, key_id) catch return ERR_INVALID_INPUT;
    defer alloc.free(invoice);
    return copyToOut(invoice, out_buf, out_len);
}

/// BRC-42 Type-42 key derivation: derive a child private key.
/// privkey: 32-byte private key, counterparty_pubkey: 33-byte compressed pubkey,
/// invoice: BRC-43 invoice string. out_privkey: 32 bytes.
export fn bsvz_derive_child_privkey(
    privkey: [*c]const u8,
    counterparty_pubkey: [*c]const u8,
    invoice_ptr: [*c]const u8,
    invoice_len: usize,
    out_privkey: [*c]u8,
) c_int {
    const pk = ec.PrivateKey.fromBytes(privkey[0..32].*) catch return ERR_CRYPTO;
    const cpub = ec.PublicKey.fromSec1(counterparty_pubkey[0..33]) catch return ERR_CRYPTO;
    const invoice = invoice_ptr[0..invoice_len];
    const derived = pk.deriveChild(cpub, invoice) catch return ERR_CRYPTO;
    @memcpy(out_privkey[0..32], &derived.toBytes());
    return OK;
}

/// BRC-42 Type-42 public key derivation: derive a child public key.
/// pubkey: 33-byte compressed pubkey, counterparty_privkey: 32-byte private key,
/// invoice: BRC-43 invoice string. out_pubkey: 33 bytes.
export fn bsvz_derive_child_pubkey(
    pubkey: [*c]const u8,
    counterparty_privkey: [*c]const u8,
    invoice_ptr: [*c]const u8,
    invoice_len: usize,
    out_pubkey: [*c]u8,
) c_int {
    const pub_key = ec.PublicKey.fromSec1(pubkey[0..33]) catch return ERR_CRYPTO;
    const cpriv = ec.PrivateKey.fromBytes(counterparty_privkey[0..32].*) catch return ERR_CRYPTO;
    const invoice = invoice_ptr[0..invoice_len];
    const derived = pub_key.deriveChild(cpriv, invoice) catch return ERR_CRYPTO;
    @memcpy(out_pubkey[0..33], &derived.toCompressedSec1());
    return OK;
}

// ── Key operations ──────────────────────────────────────────────────────

/// Get the compressed (33-byte) public key from a 32-byte private key.
/// out_pubkey must be at least 33 bytes.
export fn bsvz_privkey_to_pubkey(
    privkey: [*c]const u8,
    out_pubkey: [*c]u8,
) c_int {
    const pk = crypto.PrivateKey.fromBytes(privkey[0..32].*) catch return ERR_CRYPTO;
    const pubk = pk.publicKey() catch return ERR_CRYPTO;
    @memcpy(out_pubkey[0..33], &pubk.bytes);
    return OK;
}

/// Encode a compressed public key (33 bytes) as a P2PKH address (mainnet).
/// out_addr must be at least 40 bytes. out_addr_len receives actual length.
export fn bsvz_pubkey_to_address(
    pubkey: [*c]const u8,
    pubkey_len: usize,
    out_addr: [*c]u8,
    out_addr_len: *usize,
) c_int {
    if (pubkey_len != 33) return ERR_INVALID_INPUT;
    const pk = crypto.PublicKey{ .bytes = pubkey[0..33].* };
    const addr = compat_address.encodeP2pkhFromPublicKey(alloc, .mainnet, pk) catch return ERR_CRYPTO;
    defer alloc.free(addr);
    return copyToOut(addr, out_addr, out_addr_len);
}

/// Encode a 32-byte private key as WIF (compressed, mainnet).
/// out_wif must be at least 60 bytes. out_wif_len receives actual length.
export fn bsvz_privkey_to_wif(
    privkey: [*c]const u8,
    out_wif: [*c]u8,
    out_wif_len: *usize,
) c_int {
    const pk = crypto.PrivateKey.fromBytes(privkey[0..32].*) catch return ERR_CRYPTO;
    const wif = compat_wif.encode(alloc, .mainnet, pk, true) catch return ERR_ALLOC;
    defer alloc.free(wif);
    return copyToOut(wif, out_wif, out_wif_len);
}

/// Decode a WIF string to a 32-byte private key.
/// out_privkey must be at least 32 bytes.
export fn bsvz_wif_to_privkey(
    wif_ptr: [*c]const u8,
    wif_len: usize,
    out_privkey: [*c]u8,
) c_int {
    const wif_str = wif_ptr[0..wif_len];
    const decoded = compat_wif.decode(alloc, wif_str) catch return ERR_INVALID_INPUT;
    @memcpy(out_privkey[0..32], &decoded.private_key.toBytes());
    return OK;
}

// ── BSM (legacy, kept for compat) ───────────────────────────────────────

/// Sign a message using Bitcoin Signed Message (BSM) format.
/// Returns a 65-byte compact signature. out_sig must be at least 65 bytes.
export fn bsvz_bsm_sign(
    privkey: [*c]const u8,
    msg_ptr: [*c]const u8,
    msg_len: usize,
    out_sig: [*c]u8,
    out_sig_len: *usize,
) c_int {
    const pk = crypto.PrivateKey.fromBytes(privkey[0..32].*) catch return ERR_CRYPTO;
    const message = msg_ptr[0..msg_len];
    const sig = compat_bsm.signMessage(pk, message, alloc) catch return ERR_CRYPTO;
    @memcpy(out_sig[0..65], &sig);
    out_sig_len.* = 65;
    return OK;
}

/// Verify a BSM signature against a P2PKH address string.
/// Returns 0 if valid, negative if invalid.
export fn bsvz_bsm_verify(
    addr_ptr: [*c]const u8,
    addr_len: usize,
    msg_ptr: [*c]const u8,
    msg_len: usize,
    sig_ptr: [*c]const u8,
    sig_len: usize,
) c_int {
    if (sig_len != 65) return ERR_INVALID_INPUT;
    const addr_str = addr_ptr[0..addr_len];
    const message = msg_ptr[0..msg_len];
    var sig65: [65]u8 = undefined;
    @memcpy(&sig65, sig_ptr[0..65]);
    compat_bsm.verifyMessage(alloc, .mainnet, addr_str, sig65, message) catch return ERR_CRYPTO;
    return OK;
}

// ── BRC-77 signed messages ──────────────────────────────────────────────

/// BRC-77: Sign a message for "anyone" (no specific recipient).
/// out_sig must be at least 256 bytes. out_sig_len receives actual length.
export fn bsvz_brc77_sign_anyone(
    signer_privkey: [*c]const u8,
    msg_ptr: [*c]const u8,
    msg_len: usize,
    out_sig: [*c]u8,
    out_sig_len: *usize,
) c_int {
    const signer = ec.PrivateKey.fromBytes(signer_privkey[0..32].*) catch return ERR_CRYPTO;
    const message = msg_ptr[0..msg_len];
    const sig = msg_signed.signAlloc(alloc, message, signer, null) catch return ERR_CRYPTO;
    defer alloc.free(sig);
    return copyToOut(sig, out_sig, out_sig_len);
}

/// BRC-77: Sign a message for a specific recipient (33-byte compressed pubkey).
/// out_sig must be at least 256 bytes. out_sig_len receives actual length.
export fn bsvz_brc77_sign_for(
    signer_privkey: [*c]const u8,
    recipient_pubkey: [*c]const u8,
    msg_ptr: [*c]const u8,
    msg_len: usize,
    out_sig: [*c]u8,
    out_sig_len: *usize,
) c_int {
    const signer = ec.PrivateKey.fromBytes(signer_privkey[0..32].*) catch return ERR_CRYPTO;
    const recipient = ec.PublicKey.fromSec1(recipient_pubkey[0..33]) catch return ERR_CRYPTO;
    const message = msg_ptr[0..msg_len];
    const sig = msg_signed.signAlloc(alloc, message, signer, recipient) catch return ERR_CRYPTO;
    defer alloc.free(sig);
    return copyToOut(sig, out_sig, out_sig_len);
}

/// BRC-77: Verify an "anyone" signed message. Returns 0 if valid.
export fn bsvz_brc77_verify_anyone(
    msg_ptr: [*c]const u8,
    msg_len: usize,
    sig_ptr: [*c]const u8,
    sig_len: usize,
) c_int {
    const message = msg_ptr[0..msg_len];
    const sig = sig_ptr[0..sig_len];
    const valid = msg_signed.verify(message, sig, null) catch return ERR_CRYPTO;
    if (!valid) return ERR_CRYPTO;
    return OK;
}

/// BRC-77: Verify a targeted signed message. Provide recipient privkey (32 bytes).
/// Returns 0 if valid, negative if invalid.
export fn bsvz_brc77_verify_for(
    msg_ptr: [*c]const u8,
    msg_len: usize,
    sig_ptr: [*c]const u8,
    sig_len: usize,
    recipient_privkey: [*c]const u8,
) c_int {
    const message = msg_ptr[0..msg_len];
    const sig = sig_ptr[0..sig_len];
    const recipient = ec.PrivateKey.fromBytes(recipient_privkey[0..32].*) catch return ERR_CRYPTO;
    const valid = msg_signed.verify(message, sig, recipient) catch return ERR_CRYPTO;
    if (!valid) return ERR_CRYPTO;
    return OK;
}
