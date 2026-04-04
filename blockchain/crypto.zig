const std = @import("std");
const hash_mod = @import("hash.zig");
const sig_mod = @import("signature.zig");

pub const HASH_SIZE = hash_mod.digest_length;
pub const public_key_size = sig_mod.public_key_size;
pub const secret_key_size = sig_mod.secret_key_size;
pub const signature_size = sig_mod.signature_size;

pub const PublicKey = sig_mod.PublicKey;
pub const SecretKey = sig_mod.SecretKey;
pub const Signature = sig_mod.Signature;
pub const KeyPair = sig_mod.KeyPair;

pub fn hash(data: []const u8) [HASH_SIZE]u8 {
    return hash_mod.hash(data);
}

pub fn generateKeyPair() KeyPair {
    return sig_mod.generateKeyPair();
}

pub fn sign(message: []const u8, keypair: KeyPair) !Signature {
    return sig_mod.sign(message, keypair);
}

pub fn verify(sig: Signature, message: []const u8, public_key: PublicKey) bool {
    return sig_mod.verify(sig, message, public_key);
}
