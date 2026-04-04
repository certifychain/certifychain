const std = @import("std");
const ipfs = @import("ipfs");
const transaction = @import("transaction.zig");
const signature = @import("signature.zig");

pub const Certificate = struct {
    id: []const u8,
    issuer_public_key: [32]u8,
    recipient_public_key: [32]u8,
    recipient_name: []const u8,
    issuer_name: []const u8,
    metadata_cid: ?[]const u8,
    issue_date: u64,
    expiry_date: u64,
    revoked: bool,
};

pub const CertificateStore = struct {
    allocator: std.mem.Allocator,
    gateway: ipfs.GatewayClient,

    pub fn init(allocator: std.mem.Allocator, gateway_url: []const u8) CertificateStore {
        return .{
            .allocator = allocator,
            .gateway = ipfs.GatewayClient.init(allocator, gateway_url),
        };
    }

    pub fn deinit(self: *CertificateStore) void {
        self.gateway.deinit();
    }

    pub fn storeMetadata(self: *CertificateStore, metadata: []const u8) ![]const u8 {
        const mh = try ipfs.multihash.createMultihash(self.allocator, metadata, .sha2_256);
        defer self.allocator.free(mh.digest);
        const cid = ipfs.CID.v1(.dag_cbor, mh);
        const cid_str = try cid.toString(self.allocator);
        return cid_str;
    }

    pub fn storeFile(self: *CertificateStore, file_data: []const u8) ![]const u8 {
        const mh = try ipfs.multihash.createMultihash(self.allocator, file_data, .sha2_256);
        defer self.allocator.free(mh.digest);
        const cid = ipfs.CID.v1(.raw, mh);
        const cid_str = try cid.toString(self.allocator);
        return cid_str;
    }

    pub fn retrieveFile(self: *CertificateStore, cid_str: []const u8) ![]u8 {
        return try self.gateway.fetch(cid_str);
    }

    pub fn createIssueTransaction(
        self: *CertificateStore,
        issuer_keypair: signature.KeyPair,
        recipient_public_key: [32]u8,
        recipient_name: []const u8,
        metadata: []const u8,
        expiry_date: u64,
    ) !transaction.Transaction {
        const cert_id = try self.generateCertificateId();
        errdefer self.allocator.free(cert_id);

        const metadata_cid = try self.storeMetadata(metadata);

        const cert_data = transaction.CertificateData{
            .recipient_public_key = recipient_public_key,
            .certificate_id = cert_id,
            .issuer_name = "CertifyChain",
            .recipient_name = recipient_name,
            .issue_date = @as(u64, @intCast(std.time.timestamp())),
            .expiry_date = expiry_date,
            .metadata = metadata_cid,
            .ipfs_cid = metadata_cid,
        };

        return try transaction.Transaction.createIssueTransaction(
            issuer_keypair.public_key.bytes,
            cert_data,
            issuer_keypair,
        );
    }

    fn generateCertificateId(self: *CertificateStore) ![]u8 {
        var random_bytes: [16]u8 = undefined;
        std.crypto.random.bytes(&random_bytes);
        const hex = std.fmt.bytesToHex(random_bytes, .lower);
        const id = try std.fmt.allocPrint(self.allocator, "CERT-{s}", .{&hex});
        return id;
    }
};

test "storeMetadata generates CID" {
    const allocator = std.testing.allocator;
    var store = CertificateStore.init(allocator, "https://cloudflare-ipfs.com");
    defer store.deinit();

    const metadata = "{\"name\":\"Test Certificate\",\"degree\":\"BSc\"}";
    const cid = try store.storeMetadata(metadata);
    defer allocator.free(cid);

    try std.testing.expect(cid.len > 0);
    try std.testing.expect(std.mem.startsWith(u8, cid, "bafy"));
}

test "storeFile generates CID" {
    const allocator = std.testing.allocator;
    var store = CertificateStore.init(allocator, "https://cloudflare-ipfs.com");
    defer store.deinit();

    const file_data = "certificate image data";
    const cid = try store.storeFile(file_data);
    defer allocator.free(cid);

    try std.testing.expect(cid.len > 0);
    try std.testing.expect(std.mem.startsWith(u8, cid, "bafy"));
}

test "generateCertificateId format" {
    const allocator = std.testing.allocator;
    var store = CertificateStore.init(allocator, "https://cloudflare-ipfs.com");
    defer store.deinit();

    const id = try store.generateCertificateId();
    defer allocator.free(id);

    try std.testing.expect(std.mem.startsWith(u8, id, "CERT-"));
    try std.testing.expect(id.len == 37);
}
