pub const Preimage = struct {
    raw: []const u8,

    pub fn parse(raw: []const u8) Preimage {
        return .{ .raw = raw };
    }
};
