const std = @import("std");

pub const Ed25519 = std.crypto.sign.Ed25519;

pub const PublicKey = Ed25519.PublicKey;
pub const SecretKey = Ed25519.SecretKey;
pub const Signature = Ed25519.Signature;
pub const KeyPair = Ed25519.KeyPair;

pub const public_key_size = 32;
pub const secret_key_size = 64;
pub const signature_size = 64;

pub fn generateKeyPair() KeyPair {
    return Ed25519.KeyPair.generate();
}

pub fn sign(message: []const u8, keypair: KeyPair) !Signature {
    return keypair.sign(message, null);
}

pub fn verify(sig: Signature, message: []const u8, public_key: PublicKey) bool {
    sig.verify(message, public_key) catch return false;
    return true;
}

test "generateKeyPair" {
    const kp = generateKeyPair();
    try std.testing.expect(kp.public_key.bytes.len == public_key_size);
    try std.testing.expect(kp.secret_key.bytes.len == secret_key_size);
}

test "sign and verify" {
    const kp = generateKeyPair();
    const sig = try sign("test message", kp);
    try std.testing.expect(verify(sig, "test message", kp.public_key));
}

test "verify rejects tampered" {
    const kp = generateKeyPair();
    const sig = try sign("original", kp);
    try std.testing.expect(!verify(sig, "tampered", kp.public_key));
}

test "verify rejects wrong key" {
    const kp1 = generateKeyPair();
    const kp2 = generateKeyPair();
    const sig = try sign("message", kp1);
    try std.testing.expect(!verify(sig, "message", kp2.public_key));
}

test "public key roundtrip" {
    const kp = generateKeyPair();
    const bytes = kp.public_key.toBytes();
    const reconstructed = try PublicKey.fromBytes(bytes);
    try std.testing.expect(std.mem.eql(u8, &kp.public_key.bytes, &reconstructed.bytes));
}
