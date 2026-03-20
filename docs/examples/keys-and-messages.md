# Keys and Messages

## WIF and addresses

```zig
const priv = try bsvz.primitives.ec.PrivateKey.fromWif(allocator, wif_text);
const pub = try priv.publicKey();

const address = try bsvz.compat.address.encodeP2pkhFromPublicKey(allocator, .mainnet, pub);
defer allocator.free(address);
```

You can also encode directly from a hash160 or decode an address back to its P2PKH payload with:

- `bsvz.compat.address.encodeP2pkh(...)`
- `bsvz.compat.address.decodeP2pkh(...)`

## BIP39 -> BIP32

```zig
const master = try bsvz.primitives.bip32.masterFromMnemonic(
    allocator,
    mnemonic,
    "",
    bsvz.primitives.bip32.Versions.mainnet,
);

const child = try master.derivePath("44'/0'/0'/0/0");
const xpub = try (try child.neuter()).toStringAlloc(allocator);
defer allocator.free(xpub);
```

`derivePath(...)` expects path segments relative to the current key, so do not include a leading `m/`.

## Type-42 and ECDH

```zig
const alice_child = try alice_priv.deriveChild(bob_pub, "2-example");
const bob_child_pub = try bob_pub.deriveChild(alice_priv, "2-example");
const shared = try alice_priv.deriveSharedSecret(bob_pub);
```

Main entry points:

- `bsvz.primitives.ec.PrivateKey`
- `bsvz.primitives.ec.PublicKey`
- `deriveChild(...)`
- `deriveSharedSecret(...)`

## BRC-77 signed messages

```zig
const sig = try bsvz.message.signed.signAlloc(allocator, message, sender_priv, recipient_pub);
defer allocator.free(sig);

const ok = try bsvz.message.signed.verify(message, sig, recipient_priv);
```

For legacy Bitcoin Signed Message compatibility, use:

- `bsvz.compat.bsm.signMessage(...)`
- `bsvz.compat.bsm.verifyMessage(...)`
- `bsvz.compat.bsm.recoverPubkey(...)`

## BRC-78 encrypted messages

```zig
const enc = try bsvz.message.encrypted.encryptAlloc(allocator, message, sender_priv, recipient_pub);
defer allocator.free(enc);

const dec = try bsvz.message.encrypted.decryptAlloc(allocator, enc, recipient_priv);
defer allocator.free(dec);
```

For Electrum / Bitcore ECIES compatibility, use:

- `bsvz.compat.ecies.electrumEncryptAlloc(...)`
- `bsvz.compat.ecies.electrumDecryptAlloc(...)`
- `bsvz.compat.ecies.bitcoreEncryptAlloc(...)`
- `bsvz.compat.ecies.bitcoreDecryptAlloc(...)`
