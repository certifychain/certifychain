const std = @import("std");
const h = @import("hash.zig");
const sig = @import("signature.zig");

pub const HASH_SIZE = h.digest_length;
pub const Hash = [HASH_SIZE]u8;
pub const public_key_size = sig.public_key_size;
pub const signature_size = sig.signature_size;

pub const TxType = enum {
    issue_certificate,
    revoke_certificate,
    transfer_ownership,
};

pub const CertData = struct {
    recipient_public_key: [public_key_size]u8,
    certificate_id: []const u8,
    issuer_name: []const u8,
    recipient_name: []const u8,
    issue_date: u64,
    expiry_date: u64,
    metadata: []const u8,
    ipfs_cid: ?[]const u8,
};

pub const Transaction = struct {
    const Self = @This();

    tx_type: TxType,
    sender_public_key: [public_key_size]u8,
    cert_data: ?CertData,
    timestamp: u64,
    signature: [signature_size]u8,
    hash: Hash,

    pub fn issue(
        sender_public_key: [public_key_size]u8,
        cert_data: CertData,
        kp: sig.KeyPair,
    ) !Self {
        var tx = Self{
            .tx_type = .issue_certificate,
            .sender_public_key = sender_public_key,
            .cert_data = cert_data,
            .timestamp = @as(u64, @intCast(std.time.timestamp())),
            .signature = undefined,
            .hash = undefined,
        };
        tx.signature = try tx.sign(kp);
        tx.hash = tx.hashTransaction();
        return tx;
    }

    pub fn revoke(
        sender_public_key: [public_key_size]u8,
        certificate_id: []const u8,
        kp: sig.KeyPair,
    ) !Self {
        const cert_data = CertData{
            .recipient_public_key = [_]u8{0} ** public_key_size,
            .certificate_id = certificate_id,
            .issuer_name = "",
            .recipient_name = "",
            .issue_date = 0,
            .expiry_date = 0,
            .metadata = "",
            .ipfs_cid = null,
        };
        var tx = Self{
            .tx_type = .revoke_certificate,
            .sender_public_key = sender_public_key,
            .cert_data = cert_data,
            .timestamp = @as(u64, @intCast(std.time.timestamp())),
            .signature = undefined,
            .hash = undefined,
        };
        tx.signature = try tx.sign(kp);
        tx.hash = tx.hashTransaction();
        return tx;
    }

    pub fn hashTransaction(self: *const Self) Hash {
        var buf: [256]u8 = undefined;
        var offset: usize = 0;

        buf[offset] = @intFromEnum(self.tx_type);
        offset += 1;

        @memcpy(buf[offset..][0..public_key_size], &self.sender_public_key);
        offset += public_key_size;

        @memcpy(buf[offset..][0..8], std.mem.asBytes(&self.timestamp));
        offset += 8;

        if (self.cert_data) |cert| {
            @memcpy(buf[offset..][0..public_key_size], &cert.recipient_public_key);
            offset += public_key_size;

            const id_len = @min(cert.certificate_id.len, 64);
            @memcpy(buf[offset..][0..id_len], cert.certificate_id[0..id_len]);
            offset += id_len;
        }

        return h.hash(buf[0..offset]);
    }

    fn sign(self: *Self, kp: sig.KeyPair) ![signature_size]u8 {
        const data_hash = self.hashTransaction();
        const sig_obj = try sig.sign(&data_hash, kp);
        return sig_obj.toBytes();
    }

    pub fn verifySignature(self: *const Self) bool {
        const data_hash = self.hashTransaction();
        const sig_obj = sig.Signature.fromBytes(self.signature);
        const pk = sig.PublicKey.fromBytes(self.sender_public_key) catch return false;
        return sig.verify(sig_obj, &data_hash, pk);
    }

    pub fn valid(self: *const Self) bool {
        if (self.cert_data) |cert| {
            if (self.tx_type == .issue_certificate) {
                if (cert.expiry_date <= cert.issue_date) return false;
                if (cert.certificate_id.len == 0) return false;
                if (cert.issuer_name.len == 0) return false;
                if (cert.recipient_name.len == 0) return false;
            }
        }
        return self.verifySignature();
    }
};

test "Transaction issue" {
    const kp = sig.generateKeyPair();
    const cert_data = CertData{
        .recipient_public_key = kp.public_key.bytes,
        .certificate_id = "CERT-001",
        .issuer_name = "University",
        .recipient_name = "John Doe",
        .issue_date = 1700000000,
        .expiry_date = 1731532800,
        .metadata = "{}",
        .ipfs_cid = null,
    };
    const tx = try Transaction.issue(kp.public_key.bytes, cert_data, kp);
    try std.testing.expect(tx.tx_type == .issue_certificate);
}

test "Transaction signature" {
    const kp = sig.generateKeyPair();
    const cert_data = CertData{
        .recipient_public_key = kp.public_key.bytes,
        .certificate_id = "CERT-001",
        .issuer_name = "University",
        .recipient_name = "John Doe",
        .issue_date = 1700000000,
        .expiry_date = 1731532800,
        .metadata = "{}",
        .ipfs_cid = null,
    };
    const tx = try Transaction.issue(kp.public_key.bytes, cert_data, kp);
    try std.testing.expect(tx.verifySignature());
}

test "Transaction hash deterministic" {
    const kp = sig.generateKeyPair();
    const cert_data = CertData{
        .recipient_public_key = kp.public_key.bytes,
        .certificate_id = "CERT-001",
        .issuer_name = "University",
        .recipient_name = "John Doe",
        .issue_date = 1700000000,
        .expiry_date = 1731532800,
        .metadata = "{}",
        .ipfs_cid = null,
    };
    const tx = try Transaction.issue(kp.public_key.bytes, cert_data, kp);
    const h1 = tx.hashTransaction();
    const h2 = tx.hashTransaction();
    try std.testing.expect(std.mem.eql(u8, &h1, &h2));
}

test "Transaction revoke" {
    const kp = sig.generateKeyPair();
    const tx = try Transaction.revoke(kp.public_key.bytes, "CERT-001", kp);
    try std.testing.expect(tx.tx_type == .revoke_certificate);
    try std.testing.expect(tx.verifySignature());
}

test "Transaction invalid - bad expiry" {
    const kp = sig.generateKeyPair();
    const cert_data = CertData{
        .recipient_public_key = kp.public_key.bytes,
        .certificate_id = "CERT-001",
        .issuer_name = "University",
        .recipient_name = "John Doe",
        .issue_date = 1700000000,
        .expiry_date = 1699000000,
        .metadata = "{}",
        .ipfs_cid = null,
    };
    const tx = try Transaction.issue(kp.public_key.bytes, cert_data, kp);
    try std.testing.expect(!tx.valid());
}

test "Transaction invalid - empty issuer" {
    const kp = sig.generateKeyPair();
    const cert_data = CertData{
        .recipient_public_key = kp.public_key.bytes,
        .certificate_id = "CERT-001",
        .issuer_name = "",
        .recipient_name = "John Doe",
        .issue_date = 1700000000,
        .expiry_date = 1731532800,
        .metadata = "{}",
        .ipfs_cid = null,
    };
    const tx = try Transaction.issue(kp.public_key.bytes, cert_data, kp);
    try std.testing.expect(!tx.valid());
}
