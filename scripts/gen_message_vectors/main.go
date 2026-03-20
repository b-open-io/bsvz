// Regenerate: cd $GO_SDK && go run ../bsvz/scripts/gen_message_vectors/main.go -out ../bsvz/src/message/fixtures/message_vectors.json
// Requires: github.com/bsv-blockchain/go-sdk at sibling path (or set GO_SDK).
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// Must stay aligned with go-sdk/message/signed.go
var versionBytesSigned = []byte{0x42, 0x42, 0x33, 0x01}

func signFixed(message []byte, signer *ec.PrivateKey, verifier *ec.PublicKey, keyID []byte) ([]byte, error) {
	recipientAnyone := verifier == nil
	if recipientAnyone {
		_, verifier = ec.PrivateKeyFromBytes([]byte{1})
	}
	invoiceNumber := "2-message signing-" + base64.StdEncoding.EncodeToString(keyID)
	signingPriv, err := signer.DeriveChild(verifier, invoiceNumber)
	if err != nil {
		return nil, err
	}
	hashedMessage := sha256.Sum256(message)
	signature, err := signingPriv.Sign(hashedMessage[:])
	if err != nil {
		return nil, err
	}
	senderPublicKey := signer.PubKey()
	sig := append(append([]byte{}, versionBytesSigned...), senderPublicKey.Compressed()...)
	if recipientAnyone {
		sig = append(sig, 0)
	} else {
		sig = append(sig, verifier.Compressed()...)
	}
	sig = append(sig, keyID...)
	signatureDER, err := signature.ToDER()
	if err != nil {
		return nil, err
	}
	sig = append(sig, signatureDER...)
	return sig, nil
}

// Must stay aligned with go-sdk/message/encrypted.go
func encryptFixed(message []byte, sender *ec.PrivateKey, recipient *ec.PublicKey, keyID []byte) ([]byte, error) {
	invoiceNumber := "2-message encryption-" + base64.StdEncoding.EncodeToString(keyID)
	signingPriv, err := sender.DeriveChild(recipient, invoiceNumber)
	if err != nil {
		return nil, err
	}
	recipientPub, err := recipient.DeriveChild(sender, invoiceNumber)
	if err != nil {
		return nil, err
	}
	sharedSecret, err := signingPriv.DeriveSharedSecret(recipientPub)
	if err != nil {
		return nil, err
	}
	priv := ec.NewSymmetricKey(sharedSecret.Compressed()[1:])
	skey := ec.NewSymmetricKey(priv.ToBytes())
	ciphertext, err := skey.Encrypt(message)
	if err != nil {
		return nil, err
	}
	version, err := hex.DecodeString("42421033")
	if err != nil {
		return nil, err
	}
	out := append(append(append(append(append([]byte{}, version...), sender.PubKey().Compressed()...), recipient.Compressed()...), keyID...), ciphertext...)
	return out, nil
}

type vec77 struct {
	Case               string `json:"case"`
	MessageHex         string `json:"message_hex"`
	SenderPrivHex      string `json:"sender_priv_hex"`
	RecipientPrivHex   string `json:"recipient_priv_hex,omitempty"`
	Anyone             bool   `json:"anyone"`
	KeyIDHex           string `json:"key_id_hex"`
	SignatureHex       string `json:"signature_hex"`
	ExpectedInvoiceB64 string `json:"expected_invoice_suffix_b64"`
}

type vec78 struct {
	Case             string `json:"case"`
	PlaintextHex     string `json:"plaintext_hex"`
	SenderPrivHex    string `json:"sender_priv_hex"`
	RecipientPrivHex string `json:"recipient_priv_hex"`
	KeyIDHex         string `json:"key_id_hex"`
	CiphertextHex    string `json:"ciphertext_hex"`
}

type doc struct {
	BRC77 []vec77 `json:"brc77"`
	BRC78 []vec78 `json:"brc78"`
	Note  string  `json:"_generated_note"`
}

func must32(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	if len(b) != 32 {
		panic("want 32 bytes")
	}
	return b
}

func main() {
	outPath := flag.String("out", "", "write JSON here")
	flag.Parse()
	if *outPath == "" {
		fmt.Fprintln(os.Stderr, "usage: -out path.json")
		os.Exit(1)
	}

	sender15 := bytes.Repeat([]byte{0x0f}, 32)
	recipient21 := bytes.Repeat([]byte{0x15}, 32)
	senderPriv, _ := ec.PrivateKeyFromBytes(sender15)
	_, recipientPub := ec.PrivateKeyFromBytes(recipient21)

	msg := []byte{1, 2, 4, 8, 16, 32}
	key77r := must32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	sigR, err := signFixed(msg, senderPriv, recipientPub, key77r)
	if err != nil {
		panic(err)
	}
	invR := base64.StdEncoding.EncodeToString(key77r)

	key77a := must32("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f")
	sigA, err := signFixed(msg, senderPriv, nil, key77a)
	if err != nil {
		panic(err)
	}
	invA := base64.StdEncoding.EncodeToString(key77a)

	pt78 := []byte("hello brc-78 vectors from go-sdk")
	key78 := must32("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf")
	ct78, err := encryptFixed(pt78, senderPriv, recipientPub, key78)
	if err != nil {
		panic(err)
	}

	emptyPt := []byte{}
	key78b := must32("c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf")
	ct78empty, err := encryptFixed(emptyPt, senderPriv, recipientPub, key78b)
	if err != nil {
		panic(err)
	}

	d := doc{
		Note: "Regenerate with scripts/gen_message_vectors/main.go from go-sdk module root. BRC-78 blobs include random AES-GCM IVs from a single Go run.",
		BRC77: []vec77{
			{
				Case:               "with_recipient",
				MessageHex:         hex.EncodeToString(msg),
				SenderPrivHex:      hex.EncodeToString(sender15),
				RecipientPrivHex:   hex.EncodeToString(recipient21),
				Anyone:             false,
				KeyIDHex:           hex.EncodeToString(key77r),
				SignatureHex:       hex.EncodeToString(sigR),
				ExpectedInvoiceB64: invR,
			},
			{
				Case:               "anyone",
				MessageHex:         hex.EncodeToString(msg),
				SenderPrivHex:      hex.EncodeToString(sender15),
				Anyone:             true,
				KeyIDHex:           hex.EncodeToString(key77a),
				SignatureHex:       hex.EncodeToString(sigA),
				ExpectedInvoiceB64: invA,
			},
		},
		BRC78: []vec78{
			{
				Case:             "text_plain",
				PlaintextHex:     hex.EncodeToString(pt78),
				SenderPrivHex:    hex.EncodeToString(sender15),
				RecipientPrivHex: hex.EncodeToString(recipient21),
				KeyIDHex:         hex.EncodeToString(key78),
				CiphertextHex:    hex.EncodeToString(ct78),
			},
			{
				Case:             "empty_plaintext",
				PlaintextHex:     "",
				SenderPrivHex:    hex.EncodeToString(sender15),
				RecipientPrivHex: hex.EncodeToString(recipient21),
				KeyIDHex:         hex.EncodeToString(key78b),
				CiphertextHex:    hex.EncodeToString(ct78empty),
			},
		},
	}
	raw, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(*outPath, raw, 0o644); err != nil {
		panic(err)
	}
	fmt.Println("wrote", *outPath)
}
