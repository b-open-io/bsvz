const Script = @import("../script/script.zig").Script;
const primitives = @import("../primitives/lib.zig");

pub const Output = struct {
    satoshis: primitives.money.Satoshis,
    locking_script: Script,
};
