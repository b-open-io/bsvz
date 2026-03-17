pub fn encodeLower(bytes: []const u8, out: []u8) ![]u8 {
    const alphabet = "0123456789abcdef";
    if (out.len < bytes.len * 2) return error.NoSpaceLeft;

    for (bytes, 0..) |byte, i| {
        out[i * 2] = alphabet[byte >> 4];
        out[i * 2 + 1] = alphabet[byte & 0x0f];
    }
    return out[0 .. bytes.len * 2];
}
