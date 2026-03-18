pub const Script = struct {
    bytes: []const u8,

    pub fn init(bytes: []const u8) Script {
        return .{ .bytes = bytes };
    }

    pub fn len(self: Script) usize {
        return self.bytes.len;
    }

    pub fn isEmpty(self: Script) bool {
        return self.bytes.len == 0;
    }
};

pub const LockingScript = Script;
pub const UnlockingScript = Script;
