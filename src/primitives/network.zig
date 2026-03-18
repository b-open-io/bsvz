pub const Network = enum {
    mainnet,
    testnet,
    regtest,

    pub fn p2pkhPrefix(self: Network) u8 {
        return switch (self) {
            .mainnet => 0x00,
            .testnet, .regtest => 0x6f,
        };
    }

    pub fn wifPrefix(self: Network) u8 {
        return switch (self) {
            .mainnet => 0x80,
            .testnet, .regtest => 0xef,
        };
    }
};
