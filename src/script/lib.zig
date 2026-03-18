pub const opcode = @import("opcode.zig");
pub const bytes = @import("bytes.zig");
pub const errors = @import("errors.zig");
pub const limits = @import("limits.zig");
pub const interpreter = @import("interpreter.zig");

pub const Script = @import("script.zig").Script;
pub const ScriptNum = @import("num.zig").ScriptNum;
pub const cat = bytes.cat;
pub const substr = bytes.substr;

pub const templates = struct {
    pub const p2pkh = @import("templates/p2pkh.zig");
    pub const op_return = @import("templates/op_return.zig");
};
