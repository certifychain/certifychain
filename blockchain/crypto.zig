const std = @import("std");

pub const hash = @import("hash.zig");
pub const signature = @import("signature.zig");

pub const HASH_SIZE = hash.HASH_SIZE;
pub const PUBLIC_KEY_SIZE = signature.PUBLIC_KEY_SIZE;
pub const SECRET_KEY_SIZE = signature.SECRET_KEY_SIZE;
pub const SIGNATURE_SIZE = signature.SIGNATURE_SIZE;

pub const PublicKey = signature.PublicKey;
pub const SecretKey = signature.SecretKey;
pub const Signature = signature.Signature;

pub fn hashData(data: []const u8) [HASH_SIZE]u8 {
    return hash.hashData(data);
}

pub fn generateKeyPair() struct { public_key: PublicKey, secret_key: SecretKey } {
    return signature.generateKeyPair();
}

pub fn sign(message: []const u8, secret_key: SecretKey) Signature {
    return signature.sign(message, secret_key);
}

pub fn verify(message: []const u8, sig: Signature, public_key: PublicKey) bool {
    return signature.verify(message, sig, public_key);
}

pub fn hashToHex(hash_val: [HASH_SIZE]u8) [HASH_SIZE * 2]u8 {
    var hex: [HASH_SIZE * 2]u8 = undefined;
    @memcpy(hex[0..HASH_SIZE], std.fmt.bytesToHex(hash_val, .lower));
    return hex;
}
