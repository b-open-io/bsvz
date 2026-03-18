const Script = @import("../script/script.zig").Script;
const OutPoint = @import("outpoint.zig").OutPoint;

pub const Input = struct {
    previous_outpoint: OutPoint,
    unlocking_script: Script,
    sequence: u32,
};
