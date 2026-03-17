const std = @import("std");
const bsvz = @import("bsvz");

test "module surface resolves" {
    _ = bsvz.crypto.Hash256.zero();
    _ = bsvz.script.Script.init("");
}
