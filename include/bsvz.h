/*
 * bsvz — C ABI for the bsvz Zig BSV library.
 * Link against libbsvz_c.a produced by `zig build`.
 *
 * All functions return 0 on success, negative on failure:
 *   -1  ERR_INVALID_INPUT
 *   -2  ERR_CRYPTO
 *   -3  ERR_BUFFER_TOO_SMALL
 *   -4  ERR_ALLOC
 *   -5  ERR_INTERNAL
 */

#ifndef BSVZ_H
#define BSVZ_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── BIP39 ─────────────────────────────────────────────────────────── */

/* Generate a BIP39 mnemonic. entropy_bits: 128, 160, 192, 224, or 256.
 * out_buf must be >= 256 bytes. out_len receives actual length. */
int bsvz_mnemonic_generate(int entropy_bits, char *out_buf, size_t *out_len);

/* Derive a 64-byte seed from mnemonic + passphrase (PBKDF2).
 * out_seed must be >= 64 bytes. */
int bsvz_mnemonic_to_seed(const char *mnemonic, size_t mnemonic_len,
                           const char *passphrase, size_t pass_len,
                           unsigned char *out_seed);

/* ── BIP32 ─────────────────────────────────────────────────────────── */

/* Create master HD key from seed. out_key receives base58 xprv string.
 * out_key must be >= 120 bytes. out_key_len receives actual length. */
int bsvz_hd_from_seed(const unsigned char *seed, size_t seed_len,
                       char *out_key, size_t *out_key_len);

/* Derive child key from base58 xprv/xpub using path like "m/44'/236'/0'/0/0".
 * out_key must be >= 120 bytes. out_key_len receives actual length. */
int bsvz_hd_derive_path(const char *key, size_t key_len,
                         const char *path, size_t path_len,
                         char *out_key, size_t *out_key_len);

/* Extract raw 32-byte private key from base58 xprv.
 * out_privkey must be >= 32 bytes. */
int bsvz_hd_privkey_bytes(const char *key, size_t key_len,
                           unsigned char *out_privkey);

/* ── Type-42 / BRC-42 / BRC-43 ────────────────────────────────────── */

/* BRC-43: Format invoice number from (security, protocol_id, key_id).
 * out_buf must be >= 1300 bytes. out_len receives actual length. */
int bsvz_brc43_invoice(unsigned char security_level,
                        const char *protocol, size_t protocol_len,
                        const char *key_id, size_t key_id_len,
                        char *out_buf, size_t *out_len);

/* BRC-42 Type-42: Derive child private key.
 * privkey: 32 bytes, counterparty_pubkey: 33 bytes compressed,
 * invoice: BRC-43 string. out_privkey: 32 bytes. */
int bsvz_derive_child_privkey(const unsigned char *privkey,
                               const unsigned char *counterparty_pubkey,
                               const char *invoice, size_t invoice_len,
                               unsigned char *out_privkey);

/* BRC-42 Type-42: Derive child public key.
 * pubkey: 33 bytes compressed, counterparty_privkey: 32 bytes,
 * invoice: BRC-43 string. out_pubkey: 33 bytes. */
int bsvz_derive_child_pubkey(const unsigned char *pubkey,
                              const unsigned char *counterparty_privkey,
                              const char *invoice, size_t invoice_len,
                              unsigned char *out_pubkey);

/* ── Key operations ────────────────────────────────────────────────── */

/* Compressed (33-byte) public key from 32-byte private key.
 * out_pubkey must be >= 33 bytes. */
int bsvz_privkey_to_pubkey(const unsigned char *privkey,
                            unsigned char *out_pubkey);

/* P2PKH address (mainnet) from 33-byte compressed pubkey.
 * out_addr must be >= 40 bytes. out_addr_len receives actual length. */
int bsvz_pubkey_to_address(const unsigned char *pubkey, size_t pubkey_len,
                            char *out_addr, size_t *out_addr_len);

/* WIF (compressed, mainnet) from 32-byte private key.
 * out_wif must be >= 60 bytes. out_wif_len receives actual length. */
int bsvz_privkey_to_wif(const unsigned char *privkey,
                         char *out_wif, size_t *out_wif_len);

/* 32-byte private key from WIF string.
 * out_privkey must be >= 32 bytes. */
int bsvz_wif_to_privkey(const char *wif, size_t wif_len,
                         unsigned char *out_privkey);

/* ── BSM (legacy) ──────────────────────────────────────────────────── */

/* BSM sign. 65-byte compact sig. out_sig must be >= 65 bytes. */
int bsvz_bsm_sign(const unsigned char *privkey,
                    const char *msg, size_t msg_len,
                    unsigned char *out_sig, size_t *out_sig_len);

/* BSM verify against P2PKH address. Returns 0 if valid. */
int bsvz_bsm_verify(const char *address, size_t addr_len,
                      const char *msg, size_t msg_len,
                      const unsigned char *sig, size_t sig_len);

/* ── BRC-77 signed messages ────────────────────────────────────────── */

/* BRC-77 sign for "anyone". out_sig must be >= 256 bytes. */
int bsvz_brc77_sign_anyone(const unsigned char *signer_privkey,
                            const char *msg, size_t msg_len,
                            unsigned char *out_sig, size_t *out_sig_len);

/* BRC-77 sign for specific recipient (33-byte compressed pubkey). */
int bsvz_brc77_sign_for(const unsigned char *signer_privkey,
                         const unsigned char *recipient_pubkey,
                         const char *msg, size_t msg_len,
                         unsigned char *out_sig, size_t *out_sig_len);

/* BRC-77 verify "anyone" message. Returns 0 if valid. */
int bsvz_brc77_verify_anyone(const char *msg, size_t msg_len,
                              const unsigned char *sig, size_t sig_len);

/* BRC-77 verify targeted message. recipient_privkey: 32 bytes. */
int bsvz_brc77_verify_for(const char *msg, size_t msg_len,
                           const unsigned char *sig, size_t sig_len,
                           const unsigned char *recipient_privkey);

#ifdef __cplusplus
}
#endif

#endif /* BSVZ_H */
