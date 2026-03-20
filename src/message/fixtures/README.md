# Message test vectors

`message_vectors.json` is produced by Go so wire bytes match **github.com/bsv-blockchain/go-sdk** `message` exactly.

Regenerate from a checkout that has `go-sdk` as a sibling of `bsvz`:

```bash
mkdir -p src/message/fixtures
cd ../go-sdk
go run ../bsvz/scripts/gen_message_vectors/main.go -out ../bsvz/src/message/fixtures/message_vectors.json
```

- **BRC-77**: deterministic signatures for fixed `key_id` (mirrors `message/signed.go` without `rand.Read`). Zig verifies the **exact go-sdk DER** bytes; re-signing the same preimage may yield different DER (Go `asn1.Marshal` vs Zig ECDSA encoding / low-S), so tests assert **both** signatures verify, not byte-identical DER.
- **BRC-78**: full ciphertext blobs include a random AES-GCM IV from one Go run; Zig asserts **decrypt** parity with the embedded plaintext.
