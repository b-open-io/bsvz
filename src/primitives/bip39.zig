//! BIP39 mnemonics (English wordlist) and PBKDF2 seed derivation.
//! Behavior matches github.com/bsv-blockchain/go-sdk compat/bip39 (big.Int checksum path).

const std = @import("std");
const hex = @import("hex.zig");
const StaticStringMap = std.static_string_map.StaticStringMap;
const HmacSha512 = std.crypto.auth.hmac.sha2.HmacSha512;
const std_crypto_errors = @import("std").crypto.errors;

pub const Error = error{
    EntropyLengthInvalid,
    InvalidMnemonic,
    ChecksumIncorrect,
} || std.mem.Allocator.Error || std_crypto_errors.WeakParametersError || std_crypto_errors.OutputTooLongError;

/// English BIP39 words in index order (comptime).
pub const english: [2048][]const u8 = blk: {
    @setEvalBranchQuota(25000);
    const raw = @embedFile("bip39_english.txt");
    var words: [2048][]const u8 = undefined;
    var count: usize = 0;
    var iter = std.mem.splitScalar(u8, raw, '\n');
    while (iter.next()) |line| {
        if (line.len == 0) continue;
        var s = line;
        if (s[s.len - 1] == '\r') s = s[0 .. s.len - 1];
        words[count] = s;
        count += 1;
    }
    std.debug.assert(count == 2048);
    break :blk words;
};

const word_map: StaticStringMap(u16) = blk: {
    @setEvalBranchQuota(10000);
    var pairs: [2048]struct { []const u8, u16 } = undefined;
    for (0..2048) |i| {
        pairs[i] = .{ english[i], @intCast(i) };
    }
    break :blk StaticStringMap(u16).initComptime(pairs);
};

pub fn wordIndex(word: []const u8) ?u16 {
    return word_map.get(word);
}

fn validateEntropyBits(bit_len: usize) Error!void {
    if (bit_len % 32 != 0 or bit_len < 128 or bit_len > 256) return error.EntropyLengthInvalid;
}

pub fn newEntropy(allocator: std.mem.Allocator, bit_size: usize) Error![]u8 {
    try validateEntropyBits(bit_size);
    const n = bit_size / 8;
    const buf = try allocator.alloc(u8, n);
    std.crypto.random.bytes(buf);
    return buf;
}

/// Decodes mnemonic to entropy (checksum verified). Caller frees returned slice.
pub fn entropyFromMnemonic(allocator: std.mem.Allocator, mnemonic: []const u8) Error![]u8 {
    var buf: [32]u8 = undefined;
    const len = try entropyFromMnemonicInto(mnemonic, &buf);
    return try allocator.dupe(u8, buf[0..len]);
}

/// Writes entropy into `out` (left-padded with zeros in the sense of big-endian minimal + pad — same as Go `padByteSlice`).
/// Returns byte length of entropy (16, 20, 24, 28, or 32).
pub fn entropyFromMnemonicInto(mnemonic: []const u8, out: *[32]u8) Error!usize {
    var wbuf: [24][]const u8 = undefined;
    const nw = splitWords(mnemonic, &wbuf) orelse return error.InvalidMnemonic;
    return entropyFromWords(&wbuf, nw, out);
}

fn splitWords(mnemonic: []const u8, buf: *[24][]const u8) ?usize {
    var count: usize = 0;
    var it = std.mem.tokenizeAny(u8, mnemonic, &std.ascii.whitespace);
    while (it.next()) |w| {
        if (count >= 24) return null;
        buf[count] = w;
        count += 1;
    }
    if (count % 3 != 0 or count < 12 or count > 24) return null;
    return count;
}

fn checksumMask(n_words: usize) u32 {
    return switch (n_words) {
        12 => 15,
        15 => 31,
        18 => 63,
        21 => 127,
        24 => 255,
        else => unreachable,
    };
}

fn checksumShift(n_words: usize) u32 {
    return switch (n_words) {
        12 => 16,
        15 => 8,
        18 => 4,
        21 => 2,
        24 => 1,
        else => unreachable,
    };
}

fn entropyFromWords(words: *[24][]const u8, nw: usize, out: *[32]u8) Error!usize {
    var b: EntropyInt = 0;
    for (0..nw) |i| {
        const idx = wordIndex(words[i]) orelse return error.InvalidMnemonic;
        b = b * @as(EntropyInt, 2048) + @as(EntropyInt, idx);
    }
    const mask: EntropyInt = checksumMask(nw);
    const cs = b & mask;
    const b_ent = b / (mask + 1);

    const entropy_len = nw / 3 * 4;
    _ = u512ToBePadded(b_ent, out[0..entropy_len], entropy_len);

    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(out[0..entropy_len], &hash, .{});

    const expected_cs: u8 = if (nw == 24)
        hash[0]
    else
        hash[0] / @as(u8, @truncate(checksumShift(nw)));

    if (@as(u8, @truncate(cs)) != expected_cs) return error.ChecksumIncorrect;

    return entropy_len;
}

/// Builds a space-separated mnemonic. Caller frees.
pub fn newMnemonic(allocator: std.mem.Allocator, entropy: []const u8) Error![]u8 {
    const bit_len = entropy.len * 8;
    try validateEntropyBits(bit_len);
    const val = addChecksumU512(entropy);
    const cb = bit_len / 32;
    const sentence_len = (bit_len + cb) / 11;

    var words: [24][]const u8 = undefined;
    var v = val;
    var i: isize = @intCast(sentence_len - 1);
    while (i >= 0) : (i -= 1) {
        const idx: u16 = @truncate(@as(u32, @truncate(v & 2047)));
        words[@intCast(i)] = english[idx];
        v /= 2048;
    }

    var total: usize = sentence_len - 1;
    for (words[0..@intCast(sentence_len)]) |w| total += w.len;
    const s = try allocator.alloc(u8, total);
    errdefer allocator.free(s);

    var pos: usize = 0;
    for (words[0..@intCast(sentence_len)], 0..) |w, j| {
        if (j != 0) {
            s[pos] = ' ';
            pos += 1;
        }
        @memcpy(s[pos .. pos + w.len], w);
        pos += w.len;
    }
    return s;
}

fn addChecksumU512(entropy: []const u8) EntropyInt {
    var bits = beBytesToEntropyInt(entropy);
    const checksum_bits: u32 = @intCast(entropy.len / 4);
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(entropy, &hash, .{});
    const first = hash[0];
    var k: u32 = 0;
    while (k < checksum_bits) : (k += 1) {
        bits <<= 1;
        if ((first & (@as(u8, 1) << @intCast(7 - k))) != 0) bits |= 1;
    }
    return bits;
}

fn beBytesToEntropyInt(s: []const u8) EntropyInt {
    var x: EntropyInt = 0;
    for (s) |b| x = (x << 8) | b;
    return x;
}

/// Writes minimal big-endian `x` into `out`, left-padded with zeros to `pad_len` (Go `padByteSlice`).
fn u512ToBePadded(x: EntropyInt, out: []u8, pad_len: usize) []const u8 {
    std.debug.assert(out.len >= pad_len);
    var tmp: [64]u8 = undefined;
    const minimal = u512ToBeMinimal(x, &tmp);
    @memset(out[0..pad_len], 0);
    @memcpy(out[pad_len - minimal.len ..][0..minimal.len], minimal);
    return out[0..pad_len];
}

fn u512ToBeMinimal(x: EntropyInt, stack: *[64]u8) []const u8 {
    if (x == 0) {
        stack[63] = 0;
        return stack[63..64];
    }
    var v = x;
    var pos: usize = 64;
    while (v != 0) {
        pos -= 1;
        stack[pos] = @truncate(v & 0xff);
        v >>= 8;
    }
    return stack[pos..64];
}

pub fn newSeed(allocator: std.mem.Allocator, mnemonic: []const u8, passphrase: []const u8) Error![64]u8 {
    const salt = try std.fmt.allocPrint(allocator, "mnemonic{s}", .{passphrase});
    defer allocator.free(salt);
    var dk: [64]u8 = undefined;
    try std.crypto.pwhash.pbkdf2(&dk, mnemonic, salt, 2048, HmacSha512);
    return dk;
}

pub fn newSeedChecked(allocator: std.mem.Allocator, mnemonic: []const u8, passphrase: []const u8) Error![64]u8 {
    var scratch: [32]u8 = undefined;
    _ = try entropyFromMnemonicInto(mnemonic, &scratch);
    return newSeed(allocator, mnemonic, passphrase);
}

pub fn isMnemonicValid(mnemonic: []const u8) bool {
    var scratch: [32]u8 = undefined;
    _ = entropyFromMnemonicInto(mnemonic, &scratch) catch return false;
    return true;
}

/// `raw_entropy`: if true, returns raw entropy bytes; else entropy + checksum, padded like Go `MnemonicToByteArray`.
pub fn mnemonicToByteArrayAlloc(allocator: std.mem.Allocator, mnemonic: []const u8, raw_entropy: bool) Error![]u8 {
    var wbuf: [24][]const u8 = undefined;
    const nw = splitWords(mnemonic, &wbuf) orelse return error.InvalidMnemonic;
    var ent_buf: [32]u8 = undefined;
    const ent_len = try entropyFromWords(&wbuf, nw, &ent_buf);
    if (raw_entropy) return try allocator.dupe(u8, ent_buf[0..ent_len]);

    const eb = nw * 11;
    const csb = eb % 32;
    const full_len = (eb - csb) / 8 + 1;
    var scratch: [64]u8 = undefined;
    const with_cs = u512ToBeMinimal(addChecksumU512(ent_buf[0..ent_len]), &scratch);
    const out = try allocator.alloc(u8, full_len);
    @memset(out, 0);
    @memcpy(out[full_len - with_cs.len ..][0..with_cs.len], with_cs);
    return out;
}

const EntropyInt = std.meta.Int(.unsigned, 512);

test "bip39 official vectors (entropy, mnemonic, seed) passphrase TREZOR" {
    const allocator = std.testing.allocator;
    const passphrase = "TREZOR";

    const vectors = [_]struct { entropy_hex: []const u8, mnemonic: []const u8, seed_hex: []const u8 }{
        .{
            .entropy_hex = "00000000000000000000000000000000",
            .mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            .seed_hex = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
        },
        .{
            .entropy_hex = "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            .mnemonic = "legal winner thank year wave sausage worth useful legal winner thank yellow",
            .seed_hex = "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
        },
        .{
            .entropy_hex = "80808080808080808080808080808080",
            .mnemonic = "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
            .seed_hex = "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
        },
        .{
            .entropy_hex = "ffffffffffffffffffffffffffffffff",
            .mnemonic = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
            .seed_hex = "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
        },
        .{
            .entropy_hex = "000000000000000000000000000000000000000000000000",
            .mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
            .seed_hex = "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",
        },
        .{
            .entropy_hex = "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            .mnemonic = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
            .seed_hex = "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd",
        },
        .{
            .entropy_hex = "808080808080808080808080808080808080808080808080",
            .mnemonic = "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
            .seed_hex = "107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65",
        },
        .{
            .entropy_hex = "ffffffffffffffffffffffffffffffffffffffffffffffff",
            .mnemonic = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
            .seed_hex = "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528",
        },
        .{
            .entropy_hex = "0000000000000000000000000000000000000000000000000000000000000000",
            .mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            .seed_hex = "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
        },
        .{
            .entropy_hex = "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            .mnemonic = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
            .seed_hex = "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87",
        },
        .{
            .entropy_hex = "8080808080808080808080808080808080808080808080808080808080808080",
            .mnemonic = "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
            .seed_hex = "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f",
        },
        .{
            .entropy_hex = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            .mnemonic = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
            .seed_hex = "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
        },
        .{
            .entropy_hex = "77c2b00716cec7213839159e404db50d",
            .mnemonic = "jelly better achieve collect unaware mountain thought cargo oxygen act hood bridge",
            .seed_hex = "b5b6d0127db1a9d2226af0c3346031d77af31e918dba64287a1b44b8ebf63cdd52676f672a290aae502472cf2d602c051f3e6f18055e84e4c43897fc4e51a6ff",
        },
        .{
            .entropy_hex = "b63a9c59a6e641f288ebc103017f1da9f8290b3da6bdef7b",
            .mnemonic = "renew stay biology evidence goat welcome casual join adapt armor shuffle fault little machine walk stumble urge swap",
            .seed_hex = "9248d83e06f4cd98debf5b6f010542760df925ce46cf38a1bdb4e4de7d21f5c39366941c69e1bdbf2966e0f6e6dbece898a0e2f0a4c2b3e640953dfe8b7bbdc5",
        },
        .{
            .entropy_hex = "3e141609b97933b66a060dcddc71fad1d91677db872031e85f4c015c5e7e8982",
            .mnemonic = "dignity pass list indicate nasty swamp pool script soccer toe leaf photo multiply desk host tomato cradle drill spread actor shine dismiss champion exotic",
            .seed_hex = "ff7f3184df8696d8bef94b6c03114dbee0ef89ff938712301d27ed8336ca89ef9635da20af07d4175f2bf5f3de130f39c9d9e8dd0472489c19b1a020a940da67",
        },
        .{
            .entropy_hex = "0460ef47585604c5660618db2e6a7e7f",
            .mnemonic = "afford alter spike radar gate glance object seek swamp infant panel yellow",
            .seed_hex = "65f93a9f36b6c85cbe634ffc1f99f2b82cbb10b31edc7f087b4f6cb9e976e9faf76ff41f8f27c99afdf38f7a303ba1136ee48a4c1e7fcd3dba7aa876113a36e4",
        },
        .{
            .entropy_hex = "72f60ebac5dd8add8d2a25a797102c3ce21bc029c200076f",
            .mnemonic = "indicate race push merry suffer human cruise dwarf pole review arch keep canvas theme poem divorce alter left",
            .seed_hex = "3bbf9daa0dfad8229786ace5ddb4e00fa98a044ae4c4975ffd5e094dba9e0bb289349dbe2091761f30f382d4e35c4a670ee8ab50758d2c55881be69e327117ba",
        },
        .{
            .entropy_hex = "2c85efc7f24ee4573d2b81a6ec66cee209b2dcbd09d8eddc51e0215b0b68e416",
            .mnemonic = "clutch control vehicle tonight unusual clog visa ice plunge glimpse recipe series open hour vintage deposit universe tip job dress radar refuse motion taste",
            .seed_hex = "fe908f96f46668b2d5b37d82f558c77ed0d69dd0e7e043a5b0511c48c2f1064694a956f86360c93dd04052a8899497ce9e985ebe0c8c52b955e6ae86d4ff4449",
        },
        .{
            .entropy_hex = "eaebabb2383351fd31d703840b32e9e2",
            .mnemonic = "turtle front uncle idea crush write shrug there lottery flower risk shell",
            .seed_hex = "bdfb76a0759f301b0b899a1e3985227e53b3f51e67e3f2a65363caedf3e32fde42a66c404f18d7b05818c95ef3ca1e5146646856c461c073169467511680876c",
        },
        .{
            .entropy_hex = "7ac45cfe7722ee6c7ba84fbc2d5bd61b45cb2fe5eb65aa78",
            .mnemonic = "kiss carry display unusual confirm curtain upgrade antique rotate hello void custom frequent obey nut hole price segment",
            .seed_hex = "ed56ff6c833c07982eb7119a8f48fd363c4a9b1601cd2de736b01045c5eb8ab4f57b079403485d1c4924f0790dc10a971763337cb9f9c62226f64fff26397c79",
        },
        .{
            .entropy_hex = "4fa1a8bc3e6d80ee1316050e862c1812031493212b7ec3f3bb1b08f168cabeef",
            .mnemonic = "exile ask congress lamp submit jacket era scheme attend cousin alcohol catch course end lucky hurt sentence oven short ball bird grab wing top",
            .seed_hex = "095ee6f817b4c2cb30a5a797360a81a40ab0f9a4e25ecd672a3f58a0b5ba0687c096a6b14d2c0deb3bdefce4f61d01ae07417d502429352e27695163f7447a8c",
        },
        .{
            .entropy_hex = "18ab19a9f54a9274f03e5209a2ac8a91",
            .mnemonic = "board flee heavy tunnel powder denial science ski answer betray cargo cat",
            .seed_hex = "6eff1bb21562918509c73cb990260db07c0ce34ff0e3cc4a8cb3276129fbcb300bddfe005831350efd633909f476c45c88253276d9fd0df6ef48609e8bb7dca8",
        },
        .{
            .entropy_hex = "18a2e1d81b8ecfb2a333adcb0c17a5b9eb76cc5d05db91a4",
            .mnemonic = "board blade invite damage undo sun mimic interest slam gaze truly inherit resist great inject rocket museum chief",
            .seed_hex = "f84521c777a13b61564234bf8f8b62b3afce27fc4062b51bb5e62bdfecb23864ee6ecf07c1d5a97c0834307c5c852d8ceb88e7c97923c0a3b496bedd4e5f88a9",
        },
        .{
            .entropy_hex = "15da872c95a13dd738fbf50e427583ad61f18fd99f628c417a61cf8343c90419",
            .mnemonic = "beyond stage sleep clip because twist token leaf atom beauty genius food business side grid unable middle armed observe pair crouch tonight away coconut",
            .seed_hex = "b15509eaa2d09d3efd3e006ef42151b30367dc6e3aa5e44caba3fe4d3e352e65101fbdb86a96776b91946ff06f8eac594dc6ee1d3e82a42dfe1b40fef6bcc3fd",
        },
    };

    for (vectors) |v| {
        var entropy_buf: [32]u8 = undefined;
        const entropy = try std.fmt.hexToBytes(&entropy_buf, v.entropy_hex);

        const mnemonic = try newMnemonic(allocator, entropy);
        defer allocator.free(mnemonic);
        try std.testing.expectEqualStrings(v.mnemonic, mnemonic);

        const seed = try newSeedChecked(allocator, mnemonic, passphrase);
        var seed_hex_buf: [128]u8 = undefined;
        const seed_hex = try hex.encodeLower(&seed, &seed_hex_buf);
        try std.testing.expectEqualStrings(v.seed_hex, seed_hex);

        try std.testing.expect(isMnemonicValid(mnemonic));

        const back = try entropyFromMnemonic(allocator, mnemonic);
        defer allocator.free(back);
        try std.testing.expectEqualSlices(u8, entropy, back);
    }
}

test "bip39 invalid mnemonics" {
    const bad = [_][]const u8{
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
        "legal winner thank year wave sausage worth useful legal winner thank yellow yellow",
        "letter advice cage absurd amount doctor acoustic avoid letter advice caged above",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo, wrong",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will will will",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always.",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo why",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art art",
        "legal winner thank year wave sausage worth useful legal winner thanks year wave worth useful legal winner thank year wave sausage worth title",
        "letter advice cage absurd amount doctor acoustic avoid letters advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo voted",
        "jello better achieve collect unaware mountain thought cargo oxygen act hood bridge",
        "renew, stay, biology, evidence, goat, welcome, casual, join, adapt, armor, shuffle, fault, little, machine, walk, stumble, urge, swap",
        "dignity pass list indicate nasty",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon letter",
    };
    var scratch: [32]u8 = undefined;
    for (bad) |m| {
        try std.testing.expect(!isMnemonicValid(m));
        const res = entropyFromMnemonicInto(m, &scratch);
        if (res) |_| {
            return error.TestExpectedFailure;
        } else |err| switch (err) {
            error.InvalidMnemonic, error.ChecksumIncorrect => {},
            else => return err,
        }
    }
}

test "bip39 checksum errors match go-sdk cases" {
    var scratch: [32]u8 = undefined;
    try std.testing.expectError(error.ChecksumIncorrect, entropyFromMnemonicInto(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon yellow",
        &scratch,
    ));
    try std.testing.expectError(error.InvalidMnemonic, entropyFromMnemonicInto(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon angry",
        &scratch,
    ));
}

test "bip39 newMnemonic rejects bad entropy length" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.EntropyLengthInvalid, newMnemonic(allocator, &.{}));
    var bad17: [17]u8 = .{0} ** 17;
    try std.testing.expectError(error.EntropyLengthInvalid, newMnemonic(allocator, &bad17));
}

test "bip39 wordIndex roundtrip" {
    for (english, 0..) |w, i| {
        try std.testing.expectEqual(@as(u16, @intCast(i)), wordIndex(w).?);
    }
    try std.testing.expectEqual(@as(?u16, null), wordIndex("notaword"));
}
