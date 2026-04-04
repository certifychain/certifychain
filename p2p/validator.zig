const std = @import("std");
const blockchain = @import("blockchain");

pub const ValidationResult = enum(u8) {
    valid,
    invalid,
    pending,
    rejected,
};

pub const ValidationRequest = struct {
    request_id: []const u8,
    certificate_hash: []const u8,
    ipfs_cid: ?[]const u8,
    issuer_public_key: [32]u8,
    recipient_public_key: [32]u8,
    timestamp: u64,
};

pub const ValidationResponse = struct {
    request_id: []const u8,
    result: ValidationResult,
    message: ?[]const u8,
    validator_peer_id: [32]u8,
    signature: [64]u8,
};

pub const CertificateValidator = struct {
    allocator: std.mem.Allocator,
    db: *anyopaque,

    pub fn init(allocator: std.mem.Allocator, db: *anyopaque) CertificateValidator {
        return .{
            .allocator = allocator,
            .db = db,
        };
    }

    pub fn validateCertificate(
        _: *CertificateValidator,
        cert_data: blockchain.CertificateData,
        tx_signature: [64]u8,
    ) ValidationResult {
        if (cert_data.certificate_id.len == 0) return .invalid;
        if (cert_data.issuer_name.len == 0) return .invalid;
        if (cert_data.recipient_name.len == 0) return .invalid;
        if (cert_data.expiry_date <= cert_data.issue_date) return .invalid;

        const sig = blockchain.signature.Signature.fromBytes(tx_signature);
        const pubkey = blockchain.signature.PublicKey.fromBytes(cert_data.recipient_public_key) catch {
            return .invalid;
        };

        var tx = blockchain.Transaction{
            .transaction_type = .issue_certificate,
            .sender_public_key = cert_data.recipient_public_key,
            .certificate_data = cert_data,
            .timestamp = cert_data.issue_date,
            .signature = tx_signature,
            .hash = undefined,
        };
        const data_hash = tx.calculateHash();

        if (!blockchain.signature.verify(&data_hash, sig, pubkey)) {
            return .invalid;
        }

        return .valid;
    }
};

test "CertificateValidator validateCertificate" {
    const allocator = std.testing.allocator;
    const validator = CertificateValidator.init(allocator, undefined);
    const cert_data = blockchain.CertificateData{
        .recipient_public_key = [_]u8{0} ** 32,
        .certificate_id = "CERT-001",
        .issuer_name = "Test Issuer",
        .recipient_name = "John Doe",
        .issue_date = 1700000000,
        .expiry_date = 1731532800,
        .metadata = "{}",
        .ipfs_cid = null,
    };
    const result = validator.validateCertificate(cert_data, [_]u8{0} ** 64);
    _ = result;
}
