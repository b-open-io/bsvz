pub const opcode = @import("opcode.zig");
pub const bytes = @import("bytes.zig");
pub const chunk = @import("chunk.zig");
pub const parser = @import("parser.zig");
pub const context = @import("context.zig");
pub const errors = @import("errors.zig");
pub const limits = @import("limits.zig");
pub const engine = @import("engine.zig");
pub const thread = @import("thread.zig");
pub const interpreter = @import("interpreter.zig");
pub const bitcoin_asm = @import("asm.zig");
pub const standard = @import("standard.zig");
pub const builder = @import("builder.zig");

pub const Script = @import("script.zig").Script;
pub const LockingScript = @import("script.zig").LockingScript;
pub const UnlockingScript = @import("script.zig").UnlockingScript;
pub const ScriptNum = @import("num.zig").ScriptNum;
pub const cat = bytes.cat;
pub const substr = bytes.substr;
pub const findStateSeparatorOpReturnOffset = bytes.findStateSeparatorOpReturnOffset;
pub const executableCodePart = bytes.executableCodePart;
pub const validate = parser.validate;

pub const templates = struct {
    pub const p2pkh = @import("templates/p2pkh.zig");
    pub const op_return = @import("templates/op_return.zig");
    pub const op_true = @import("templates/op_true.zig");
    pub const pushdrop = @import("templates/pushdrop.zig");
    pub const r_puzzle = @import("templates/r_puzzle.zig");
    pub const push_tx = @import("templates/push_tx.zig");
    /// Reference: [ts-templates MultiPushDrop](https://github.com/bsv-blockchain/ts-templates/blob/master/src/MultiPushDrop.ts)
    pub const multi_pushdrop = @import("templates/multi_pushdrop.zig");
    /// Reference: [ts-templates P2MSKH](https://github.com/bsv-blockchain/ts-templates/blob/master/src/P2MSKH.ts)
    pub const p2mskh = @import("templates/p2mskh.zig");
};
