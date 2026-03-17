const script = @import("../script/lib.zig");
const OutPoint = @import("outpoint.zig").OutPoint;

pub const Input = struct {
    previous_outpoint: OutPoint,
    unlocking_script: script.Script,
    sequence: u32,
};
