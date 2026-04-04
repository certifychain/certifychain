const std = @import("std");
const crypto = @import("crypto.zig");
const hash = @import("hash.zig");
const signature = @import("signature.zig");

pub const HASH_SIZE = crypto.HASH_SIZE;
pub const Hash = [HASH_SIZE]u8;
pub const PUBLIC_KEY_SIZE = crypto.PUBLIC_KEY_SIZE;
pub const SIGNATURE_SIZE = crypto.SIGNATURE_SIZE;

pub const TransactionType = enum {
    issue_certificate,
    revoke_certificate,
    transfer_ownership,
};

pub const CertificateData = struct {
    recipient_public_key: [PUBLIC_KEY_SIZE]u8,
    certificate_id: []const u8,
    issuer_name: []const u8,
    recipient_name: []const u8,
    issue_date: u64,
    expiry_date: u64,
    metadata: []const u8,
};

pub const Transaction = struct {
    transaction_type: TransactionType,
    sender_public_key: [PUBLIC_KEY_SIZE]u8,
    certificate_data: ?CertificateData,
    timestamp: u64,
    signature: [SIGNATURE_SIZE]u8,
    hash: Hash,

    pub fn createIssueTransaction(
        sender_public_key: [PUBLIC_KEY_SIZE]u8,
        cert_data: CertificateData,
        keypair: signature.KeyPair,
    ) !Transaction {
        var tx = Transaction{
            .transaction_type = .issue_certificate,
            .sender_public_key = sender_public_key,
            .certificate_data = cert_data,
            .timestamp = @as(u64, @intCast(std.time.timestamp())),
            .signature = undefined,
            .hash = undefined,
        };
        tx.signature = try tx.sign(keypair);
        tx.hash = tx.calculateHash();
        return tx;
    }

    pub fn createRevokeTransaction(
        sender_public_key: [PUBLIC_KEY_SIZE]u8,
        certificate_id: []const u8,
        keypair: signature.KeyPair,
    ) !Transaction {
        const cert_data = CertificateData{
            .recipient_public_key = [_]u8{0} ** PUBLIC_KEY_SIZE,
            .certificate_id = certificate_id,
            .issuer_name = "",
            .recipient_name = "",
            .issue_date = 0,
            .expiry_date = 0,
            .metadata = "",
        };
        var tx = Transaction{
            .transaction_type = .revoke_certificate,
            .sender_public_key = sender_public_key,
            .certificate_data = cert_data,
            .timestamp = @as(u64, @intCast(std.time.timestamp())),
            .signature = undefined,
            .hash = undefined,
        };
        tx.signature = try tx.sign(keypair);
        tx.hash = tx.calculateHash();
        return tx;
    }

    pub fn calculateHash(self: *const Transaction) Hash {
        var buf: [512]u8 = undefined;
        var offset: usize = 0;

        buf[offset] = @intFromEnum(self.transaction_type);
        offset += 1;

        @memcpy(buf[offset..][0..PUBLIC_KEY_SIZE], &self.sender_public_key);
        offset += PUBLIC_KEY_SIZE;

        @memcpy(buf[offset..][0..8], std.mem.asBytes(&self.timestamp));
        offset += 8;

        if (self.certificate_data) |cert| {
            @memcpy(buf[offset..][0..PUBLIC_KEY_SIZE], &cert.recipient_public_key);
            offset += PUBLIC_KEY_SIZE;

            const id_len = @min(cert.certificate_id.len, 64);
            @memcpy(buf[offset..][0..id_len], cert.certificate_id[0..id_len]);
            offset += id_len;
        }

        return hash.hashData(buf[0..offset]);
    }

    fn sign(self: *Transaction, keypair: signature.KeyPair) ![SIGNATURE_SIZE]u8 {
        const data_hash = self.calculateHash();
        const sig = try signature.sign(&data_hash, keypair);
        return sig.toBytes();
    }

    pub fn verifySignature(self: *const Transaction) bool {
        const data_hash = self.calculateHash();
        const sig = signature.Signature.fromBytes(self.signature);
        const pubkey = signature.PublicKey.fromBytes(self.sender_public_key) catch return false;
        return signature.verify(&data_hash, sig, pubkey);
    }

    pub fn isValid(self: *const Transaction) bool {
        if (self.certificate_data) |cert| {
            if (self.transaction_type == .issue_certificate) {
                if (cert.expiry_date <= cert.issue_date) return false;
                if (cert.certificate_id.len == 0) return false;
                if (cert.issuer_name.len == 0) return false;
                if (cert.recipient_name.len == 0) return false;
            }
        }
        return self.verifySignature();
    }
};

test "Transaction creation" {
    const keypair = signature.generateKeyPair();
    const cert_data = CertificateData{
        .recipient_public_key = keypair.public_key.bytes,
        .certificate_id = "CERT-001",
        .issuer_name = "University",
        .recipient_name = "John Doe",
        .issue_date = 1700000000,
        .expiry_date = 1731532800,
        .metadata = "{}",
    };
    const tx = try Transaction.createIssueTransaction(
        keypair.public_key.bytes,
        cert_data,
        keypair,
    );
    try std.testing.expect(tx.transaction_type == .issue_certificate);
}

test "Transaction signature verification" {
    const keypair = signature.generateKeyPair();
    const cert_data = CertificateData{
        .recipient_public_key = keypair.public_key.bytes,
        .certificate_id = "CERT-001",
        .issuer_name = "University",
        .recipient_name = "John Doe",
        .issue_date = 1700000000,
        .expiry_date = 1731532800,
        .metadata = "{}",
    };
    const tx = try Transaction.createIssueTransaction(
        keypair.public_key.bytes,
        cert_data,
        keypair,
    );
    try std.testing.expect(tx.verifySignature());
}

test "Transaction hash is deterministic" {
    const keypair = signature.generateKeyPair();
    const cert_data = CertificateData{
        .recipient_public_key = keypair.public_key.bytes,
        .certificate_id = "CERT-001",
        .issuer_name = "University",
        .recipient_name = "John Doe",
        .issue_date = 1700000000,
        .expiry_date = 1731532800,
        .metadata = "{}",
    };
    const tx = try Transaction.createIssueTransaction(
        keypair.public_key.bytes,
        cert_data,
        keypair,
    );
    const hash1 = tx.calculateHash();
    const hash2 = tx.calculateHash();
    try std.testing.expect(std.mem.eql(u8, &hash1, &hash2));
}

test "Revoke transaction creation" {
    const keypair = signature.generateKeyPair();
    const tx = try Transaction.createRevokeTransaction(
        keypair.public_key.bytes,
        "CERT-001",
        keypair,
    );
    try std.testing.expect(tx.transaction_type == .revoke_certificate);
    try std.testing.expect(tx.verifySignature());
}

test "Invalid transaction - expiry before issue" {
    const keypair = signature.generateKeyPair();
    const cert_data = CertificateData{
        .recipient_public_key = keypair.public_key.bytes,
        .certificate_id = "CERT-001",
        .issuer_name = "University",
        .recipient_name = "John Doe",
        .issue_date = 1700000000,
        .expiry_date = 1699000000,
        .metadata = "{}",
    };
    const tx = try Transaction.createIssueTransaction(
        keypair.public_key.bytes,
        cert_data,
        keypair,
    );
    try std.testing.expect(!tx.isValid());
}

test "Invalid transaction - empty issuer name" {
    const keypair = signature.generateKeyPair();
    const cert_data = CertificateData{
        .recipient_public_key = keypair.public_key.bytes,
        .certificate_id = "CERT-001",
        .issuer_name = "",
        .recipient_name = "John Doe",
        .issue_date = 1700000000,
        .expiry_date = 1731532800,
        .metadata = "{}",
    };
    const tx = try Transaction.createIssueTransaction(
        keypair.public_key.bytes,
        cert_data,
        keypair,
    );
    try std.testing.expect(!tx.isValid());
}
