const std = @import("std");

pub const Ed25519 = std.crypto.sign.Ed25519;
pub const PUBLIC_KEY_SIZE = Ed25519.PublicKey.encoded_length;
pub const SECRET_KEY_SIZE = Ed25519.SecretKey.encoded_length;
pub const SIGNATURE_SIZE = @sizeOf(Ed25519.Signature);

pub const PublicKey = Ed25519.PublicKey;
pub const SecretKey = Ed25519.SecretKey;
pub const Signature = Ed25519.Signature;
pub const KeyPair = Ed25519.KeyPair;

pub fn generateKeyPair() KeyPair {
    return Ed25519.KeyPair.generate();
}

pub fn sign(message: []const u8, keypair: KeyPair) !Signature {
    return keypair.sign(message, null);
}

pub fn verify(message: []const u8, sig: Signature, public_key: PublicKey) bool {
    sig.verify(message, public_key) catch return false;
    return true;
}

test "generateKeyPair produces valid keys" {
    const keypair = generateKeyPair();
    try std.testing.expect(keypair.public_key.bytes.len == PUBLIC_KEY_SIZE);
    try std.testing.expect(keypair.secret_key.bytes.len == SECRET_KEY_SIZE);
}

test "sign and verify roundtrip" {
    const keypair = generateKeyPair();
    const message = "test message for signing";
    const sig = try sign(message, keypair);
    try std.testing.expect(verify(message, sig, keypair.public_key));
}

test "verify rejects wrong message" {
    const keypair = generateKeyPair();
    const message = "original message";
    const wrong_message = "tampered message";
    const sig = try sign(message, keypair);
    try std.testing.expect(!verify(wrong_message, sig, keypair.public_key));
}

test "signatures are deterministic" {
    const keypair = generateKeyPair();
    const message = "deterministic test";
    const sig1 = try sign(message, keypair);
    const sig2 = try sign(message, keypair);
    const bytes1 = sig1.toBytes();
    const bytes2 = sig2.toBytes();
    try std.testing.expect(std.mem.eql(u8, &bytes1, &bytes2));
}

test "different keys produce different signatures" {
    const keypair1 = generateKeyPair();
    const keypair2 = generateKeyPair();
    const message = "same message";
    const sig1 = try sign(message, keypair1);
    const sig2 = try sign(message, keypair2);
    const bytes1 = sig1.toBytes();
    const bytes2 = sig2.toBytes();
    try std.testing.expect(!std.mem.eql(u8, &bytes1, &bytes2));
}

test "verify rejects signature with wrong public key" {
    const keypair1 = generateKeyPair();
    const keypair2 = generateKeyPair();
    const message = "test message";
    const sig = try sign(message, keypair1);
    try std.testing.expect(!verify(message, sig, keypair2.public_key));
}

test "public key bytes roundtrip" {
    const keypair = generateKeyPair();
    const pubkey_bytes = keypair.public_key.toBytes();
    const reconstructed = try PublicKey.fromBytes(pubkey_bytes);
    try std.testing.expect(std.mem.eql(u8, &keypair.public_key.bytes, &reconstructed.bytes));
}
