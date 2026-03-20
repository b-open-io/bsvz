const std = @import("std");
const bsvz = @import("bsvz");

test "module surface resolves" {
    _ = bsvz.crypto.Hash256.zero();
    _ = bsvz.script.Script.init("");
    _ = bsvz.crypto.Point.affineBytes32;
    _ = bsvz.script.interpreter.verifyPrevoutTraced;
    _ = bsvz.script.interpreter.verifyPrevoutOutcome;
    _ = bsvz.transaction.extractOutpointBytes;
    _ = bsvz.transaction.Output.parse;
    _ = bsvz.transaction.Output.hashAll;
    _ = bsvz.primitives.brc43.formatInvoice;
    _ = bsvz.primitives.brc43.formatInvoiceProtocol;
    _ = bsvz.spv.verify;
    _ = bsvz.spv.verifyBeef;
    _ = bsvz.crypto.ecies.electrumEncryptAlloc;
}
