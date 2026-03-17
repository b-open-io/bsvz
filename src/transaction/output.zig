const script = @import("../script/lib.zig");
const primitives = @import("../primitives/lib.zig");

pub const Output = struct {
    satoshis: primitives.money.Satoshis,
    locking_script: script.Script,
};
