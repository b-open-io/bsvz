const std = @import("std");

pub const max_der_signature_len: usize = 72;

pub const DerSignature = struct {
    bytes: [max_der_signature_len]u8,
    len: usize,

    pub fn fromDer(der: []const u8) !DerSignature {
        if (der.len == 0 or der.len > max_der_signature_len) return error.InvalidEncoding;

        var out = DerSignature{
            .bytes = [_]u8{0} ** max_der_signature_len,
            .len = der.len,
        };
        @memcpy(out.bytes[0..der.len], der);
        return out;
    }

    pub fn asSlice(self: *const DerSignature) []const u8 {
        return self.bytes[0..self.len];
    }

    pub fn fromStdSignature(comptime Scheme: type, sig: Scheme.Signature) DerSignature {
        var buf: [Scheme.Signature.der_encoded_length_max]u8 = undefined;
        const der = sig.toDer(&buf);
        var out = DerSignature{
            .bytes = [_]u8{0} ** max_der_signature_len,
            .len = der.len,
        };
        @memcpy(out.bytes[0..der.len], der);
        return out;
    }

    pub fn toStdSignature(self: *const DerSignature, comptime Scheme: type) !Scheme.Signature {
        return Scheme.Signature.fromDer(self.asSlice()) catch error.InvalidEncoding;
    }
};

pub const TxSignature = struct {
    der: DerSignature,
    sighash_type: u8,

    pub fn toChecksigFormat(self: *const TxSignature, allocator: std.mem.Allocator) ![]u8 {
        var out = try allocator.alloc(u8, self.der.len + 1);
        @memcpy(out[0..self.der.len], self.der.asSlice());
        out[self.der.len] = self.sighash_type;
        return out;
    }

    pub fn fromChecksigFormat(buf: []const u8) !TxSignature {
        if (buf.len < 2) return error.InvalidEncoding;
        return .{
            .der = try DerSignature.fromDer(buf[0 .. buf.len - 1]),
            .sighash_type = buf[buf.len - 1],
        };
    }
};
