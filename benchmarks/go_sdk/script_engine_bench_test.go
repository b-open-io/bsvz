package gosdkbench

import (
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

type pairCase struct {
	locking   *script.Script
	unlocking *script.Script
}

func mustScriptHex(hex string) *script.Script {
	s, err := script.NewFromHex(hex)
	if err != nil {
		panic(err)
	}
	return s
}

var (
	arithmeticPair = pairCase{
		locking:   mustScriptHex("525393559c"),
		unlocking: mustScriptHex(""),
	}
	branchingPair = pairCase{
		locking:   mustScriptHex("516352675368529c"),
		unlocking: mustScriptHex(""),
	}
	sha256Pair = pairCase{
		locking:   mustScriptHex("20" + repeatHex("ab", 32) + "a88201209c"),
		unlocking: mustScriptHex(""),
	}
	hash160Pair = pairCase{
		locking:   mustScriptHex("14" + repeatHex("cd", 20) + "a98201149c"),
		unlocking: mustScriptHex(""),
	}
	stackOpsPair = pairCase{
		locking:   mustScriptHex("5152535455565758595a767c7b757575757575757593549c51"),
		unlocking: mustScriptHex(""),
	}
	runarArithmeticPair = pairCase{
		locking:   mustScriptHex("6e9352795279945379537995547a547a96537a537a937b937c93011b9c"),
		unlocking: mustScriptHex("01030107"),
	}
)

func repeatHex(byteHex string, count int) string {
	out := make([]byte, 0, len(byteHex)*count)
	for range count {
		out = append(out, byteHex...)
	}
	return string(out)
}

func benchmarkPair(b *testing.B, pair pairCase) {
	vm := interpreter.NewEngine()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := vm.Execute(
			interpreter.WithScripts(pair.locking, pair.unlocking),
			interpreter.WithAfterGenesis(),
			interpreter.WithForkID(),
		); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkArithmeticVerify(b *testing.B)      { benchmarkPair(b, arithmeticPair) }
func BenchmarkBranchingVerify(b *testing.B)       { benchmarkPair(b, branchingPair) }
func BenchmarkSHA256Verify(b *testing.B)          { benchmarkPair(b, sha256Pair) }
func BenchmarkHASH160Verify(b *testing.B)         { benchmarkPair(b, hash160Pair) }
func BenchmarkStackOpsVerify(b *testing.B)        { benchmarkPair(b, stackOpsPair) }
func BenchmarkRunarArithmeticVerify(b *testing.B) { benchmarkPair(b, runarArithmeticPair) }

type txCase struct {
	tx        *transaction.Transaction
	inputIdx  int
	prevTxOut *transaction.TransactionOutput
}

var p2pkhCase = func() txCase {
	tx, err := transaction.NewTransactionFromHex("0200000003a9bc457fdc6a54d99300fb137b23714d860c350a9d19ff0f571e694a419ff3a0010000006b48304502210086c83beb2b2663e4709a583d261d75be538aedcafa7766bd983e5c8db2f8b2fc02201a88b178624ab0ad1748b37c875f885930166237c88f5af78ee4e61d337f935f412103e8be830d98bb3b007a0343ee5c36daa48796ae8bb57946b1e87378ad6e8a090dfeffffff0092bb9a47e27bf64fc98f557c530c04d9ac25e2f2a8b600e92a0b1ae7c89c20010000006b483045022100f06b3db1c0a11af348401f9cebe10ae2659d6e766a9dcd9e3a04690ba10a160f02203f7fbd7dfcfc70863aface1a306fcc91bbadf6bc884c21a55ef0d32bd6b088c8412103e8be830d98bb3b007a0343ee5c36daa48796ae8bb57946b1e87378ad6e8a090dfeffffff9d0d4554fa692420a0830ca614b6c60f1bf8eaaa21afca4aa8c99fb052d9f398000000006b483045022100d920f2290548e92a6235f8b2513b7f693a64a0d3fa699f81a034f4b4608ff82f0220767d7d98025aff3c7bd5f2a66aab6a824f5990392e6489aae1e1ae3472d8dffb412103e8be830d98bb3b007a0343ee5c36daa48796ae8bb57946b1e87378ad6e8a090dfeffffff02807c814a000000001976a9143a6bf34ebfcf30e8541bbb33a7882845e5a29cb488ac76b0e60e000000001976a914bd492b67f90cb85918494767ebb23102c4f06b7088ac67000000")
	if err != nil {
		panic(err)
	}
	prevTx, err := transaction.NewTransactionFromHex("0200000001424408c9d997772e56112c731b6dc6f050cb3847c5570cea12f30bfbc7df0a010000000049483045022100fe759b2cd7f25bce4fcda4c8366891b0d9289dc5bac1cf216909c89dc324437a02204aa590b6e82764971df4fe741adf41ece4cde607cb6443edceba831060213d3641feffffff02408c380c010000001976a914f761fc0927a43f4fab5740ef39f05b1fb7786f5288ac0065cd1d000000001976a914805096c5167877a5799977d46fb9dee5891dc3cb88ac66000000")
	if err != nil {
		panic(err)
	}
	inputIdx := 0
	prevOut := prevTx.OutputIdx(int(tx.InputIdx(inputIdx).SourceTxOutIndex))
	return txCase{tx: tx, inputIdx: inputIdx, prevTxOut: prevOut}
}()

func BenchmarkP2PKHVerify(b *testing.B) {
	vm := interpreter.NewEngine()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := vm.Execute(
			interpreter.WithTx(p2pkhCase.tx, p2pkhCase.inputIdx, p2pkhCase.prevTxOut),
			interpreter.WithForkID(),
			interpreter.WithAfterGenesis(),
		); err != nil {
			b.Fatal(err)
		}
	}
}
