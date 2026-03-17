pub const BroadcastResult = struct {
    accepted: bool,
    message: ?[]const u8 = null,
};

pub const Broadcaster = struct {};
