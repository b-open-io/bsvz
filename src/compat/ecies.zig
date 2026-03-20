//! go-sdk `compat/ecies` — re-exports `crypto.ecies` (Electrum + Bitcore ECIES).
pub const electrumEncryptAlloc = @import("../crypto/ecies.zig").electrumEncryptAlloc;
pub const electrumDecryptAlloc = @import("../crypto/ecies.zig").electrumDecryptAlloc;
pub const bitcoreEncryptAlloc = @import("../crypto/ecies.zig").bitcoreEncryptAlloc;
pub const bitcoreDecryptAlloc = @import("../crypto/ecies.zig").bitcoreDecryptAlloc;
pub const Error = @import("../crypto/ecies.zig").Error;
