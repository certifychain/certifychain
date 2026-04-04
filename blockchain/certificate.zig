const std = @import("std");
const ipfs = @import("ipfs");
const signature = @import("signature.zig");
const hash = @import("hash.zig");

pub const public_key_size = 32;

pub const CertificateType = enum(u8) {
    educational,
    professional,
    vocational,
    skills_badge,
    employment,
    training,
    license,
    membership,
    award,
    custom,
};

pub const VerificationStatus = enum(u8) {
    valid,
    revoked,
    expired,
    suspended,
    pending,
};

pub const RevokeReason = enum(u8) {
    unspecified,
    key_compromise,
    affiliation_changed,
    superseded,
    cessation_of_operation,
    certificate_hold,
};

pub const Issuer = struct {
    id: []const u8,
    name: []const u8,
    public_key: [public_key_size]u8,
    url: ?[]const u8,
    logo_cid: ?[]const u8,
    description: ?[]const u8,
};

pub const Recipient = struct {
    id: []const u8,
    name: []const u8,
    email: ?[]const u8,
    public_key: [public_key_size]u8,
    orcid: ?[]const u8,
};

pub const CredentialSubject = struct {
    id: []const u8,
    name: []const u8,
    alternate_name: ?[]const u8,
    description: ?[]const u8,
    url: ?[]const u8,
    skills: ?[][]const u8,
    occupation: ?[]const u8,
    additional_properties: ?std.json.Array,
};

pub const Evidence = struct {
    id: ?[]const u8,
    type: []const u8,
    name: []const u8,
    description: ?[]const u8,
    observer: ?[]const u8,
    subject_page: ?[]const u8,
};

pub const Alignment = struct {
    framework: ?[]const u8,
    code: ?[]const u8,
    title: []const u8,
    description: ?[]const u8,
    uri: ?[]const u8,
};

pub const CertificateMetadata = struct {
    @"@context": []const u8,
    type: []const u8,
    id: []const u8,
    name: []const u8,
    description: ?[]const u8,
    encoding: []const u8,
    audience: ?[]const u8,
    subject: CredentialSubject,
    issued: u64,
    valid_from: u64,
    valid_until: ?u64,
    issuer: Issuer,
    credential_subject: CredentialSubject,
    evidence: ?[]Evidence,
    endorsements: ?[][]const u8,
    is_child_of: ?[][]const u8,
    is_wholed_for: ?[][]const u8,
    has_part: ?[][]const u8,
    aligns_with: ?[]Alignment,
    related: ?[][]const u8,
    attachments: ?[]const u8,
};

pub const Certificate = struct {
    const Self = @This();

    id: []const u8,
    issuer: Issuer,
    recipient: Recipient,
    certificate_type: CertificateType,
    metadata: CertificateMetadata,
    verification_status: VerificationStatus,
    ipfs_cid: ?[]const u8,
    attachments_cid: ?[]const u8,
    issued_at: u64,
    revoked_at: ?u64,
    revoke_reason: ?[]const u8,
    signature: [64]u8,
    blockchain_tx_hash: ?[]const u8,

    pub fn revoke(self: *Self, reason: []const u8) void {
        self.verification_status = .revoked;
        self.revoked_at = @as(u64, @intCast(std.time.timestamp()));
        self.revoke_reason = reason;
    }

    pub fn markSuspended(self: *Self) void {
        self.verification_status = .suspended;
    }

    pub fn markActive(self: *Self) void {
        self.verification_status = .valid;
    }

    pub fn expired(self: *const Self) bool {
        if (self.metadata.valid_until) |vu| {
            const now = @as(u64, @intCast(std.time.timestamp()));
            return now > vu;
        }
        return false;
    }

    pub fn valid(self: *const Self) bool {
        return self.verification_status == .valid and !self.expired();
    }

    pub fn verifySignature(self: *const Self, issuer_public_key: [public_key_size]u8) bool {
        const sig = signature.Signature.fromBytes(self.signature);
        const pk = signature.PublicKey.fromBytes(issuer_public_key) catch return false;
        const msg = self.id;
        return signature.verify(msg, sig, pk);
    }
};

pub const CertificateStore = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    gateway: ipfs.GatewayClient,

    pub fn init(allocator: std.mem.Allocator, gateway_url: []const u8) Self {
        return .{
            .allocator = allocator,
            .gateway = ipfs.GatewayClient.init(allocator, gateway_url),
        };
    }

    pub fn deinit(self: *Self) void {
        self.gateway.deinit();
    }

    pub fn storeMetadata(self: *Self, metadata: CertificateMetadata) ![]const u8 {
        const json = try self.serializeMetadata(metadata);
        defer self.allocator.free(json);

        const mh = try ipfs.multihash.createMultihash(self.allocator, json, .sha2_256);
        defer self.allocator.free(mh.digest);
        const cid = ipfs.CID.v1(.dag_json, mh);
        return try cid.toString(self.allocator);
    }

    pub fn storeFile(self: *Self, file_data: []const u8) ![]const u8 {
        const mh = try ipfs.multihash.createMultihash(self.allocator, file_data, .sha2_256);
        defer self.allocator.free(mh.digest);
        const cid = ipfs.CID.v1(.raw, mh);
        return try cid.toString(self.allocator);
    }

    pub fn fetchMetadata(self: *Self, cid_str: []const u8) ![]u8 {
        return try self.gateway.fetch(cid_str);
    }

    pub fn fetch(self: *Self, cid_str: []const u8) ![]u8 {
        return try self.gateway.fetch(cid_str);
    }

    pub fn store(self: *Self, cert: Certificate) !struct { metadata_cid: []const u8, tx_hash: []const u8 } {
        const metadata_cid = try self.storeMetadata(cert.metadata);
        const tx_hash = try self.storeMetadata(cert.metadata);

        return .{
            .metadata_cid = metadata_cid,
            .tx_hash = tx_hash,
        };
    }

    pub fn generateId(self: *Self, issuer_id: []const u8) ![]u8 {
        var random_bytes: [16]u8 = undefined;
        std.crypto.random.bytes(&random_bytes);
        const hex = std.fmt.bytesToHex(random_bytes, .lower);
        return try std.fmt.allocPrint(self.allocator, "CERT-{s}-{s}", .{ issuer_id, &hex });
    }

    fn serializeMetadata(self: *Self, metadata: CertificateMetadata) ![]u8 {
        var json = std.ArrayList(u8).init(self.allocator);
        errdefer json.deinit();

        try json.appendSlice("{\"@context\":\"https://w3id.org/openbadges/v3\",\"type\":\"BadgeClass\",");
        try std.fmt.format(json.writer(), "\"id\":\"{s}\",", .{metadata.id});
        try std.fmt.format(json.writer(), "\"name\":\"{s}\",", .{metadata.name});
        if (metadata.description) |desc| {
            try std.fmt.format(json.writer(), "\"description\":\"{s}\",", .{desc});
        }
        try std.fmt.format(json.writer(), "\"issued\":\"{d}\",", .{metadata.issued});
        try std.fmt.format(json.writer(), "\"validFrom\":\"{d}\",", .{metadata.valid_from});
        if (metadata.valid_until) |vu| {
            try std.fmt.format(json.writer(), "\"validUntil\":{d},", .{vu});
        }
        try json.appendSlice("\"issuer\":{");
        try std.fmt.format(json.writer(), "\"id\":\"{s}\",", .{metadata.issuer.id});
        try std.fmt.format(json.writer(), "\"type\":\"Profile\",");
        try std.fmt.format(json.writer(), "\"name\":\"{s}\",", .{metadata.issuer.name});
        try std.fmt.format(json.writer(), "\"url\":\"{s}\"", .{if (metadata.issuer.url) |u| u else "https://example.com"});
        try json.appendSlice("},");

        try json.appendSlice("\"credentialSubject\":{");
        try std.fmt.format(json.writer(), "\"id\":\"{s}\",", .{metadata.credential_subject.id});
        try std.fmt.format(json.writer(), "\"type\":\"Person\",");
        try std.fmt.format(json.writer(), "\"name\":\"{s}\"", .{metadata.credential_subject.name});
        try json.appendSlice("}}");

        return try json.toOwnedSlice();
    }
};

pub const CertificateRegistry = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    certificates: std.StringHashMap(CertificateRecord),
    revoked: std.StringHashMap(RevocationRecord),

    pub const CertificateRecord = struct {
        id: []const u8,
        issuer_id: []const u8,
        recipient_id: []const u8,
        status: VerificationStatus,
        ipfs_cid: ?[]const u8,
        tx_hash: []const u8,
        issued_at: u64,
        revoked_at: ?u64,
    };

    pub const RevocationRecord = struct {
        certificate_id: []const u8,
        reason: []const u8,
        revoked_at: u64,
        revoked_by: []const u8,
    };

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .certificates = std.StringHashMap(CertificateRecord).init(allocator),
            .revoked = std.StringHashMap(RevocationRecord).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        var cert_iter = self.certificates.iterator();
        while (cert_iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.certificates.deinit();

        var revoked_iter = self.revoked.iterator();
        while (revoked_iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.revoked.deinit();
    }

    pub fn register(self: *Self, record: CertificateRecord) !void {
        const id = try self.allocator.dupe(u8, record.id);
        try self.certificates.put(id, record);
    }

    pub fn revoke(self: *Self, certificate_id: []const u8, reason: []const u8, revoked_by: []const u8) !void {
        const rev_record = RevocationRecord{
            .certificate_id = certificate_id,
            .reason = reason,
            .revoked_at = @as(u64, @intCast(std.time.timestamp())),
            .revoked_by = revoked_by,
        };
        const id = try self.allocator.dupe(u8, certificate_id);
        try self.revoked.put(id, rev_record);

        if (self.certificates.getPtr(certificate_id)) |record| {
            record.status = .revoked;
            record.revoked_at = rev_record.revoked_at;
        }
    }

    pub fn get(self: *Self, certificate_id: []const u8) ?CertificateRecord {
        return self.certificates.get(certificate_id);
    }

    pub fn isRevoked(self: *Self, certificate_id: []const u8) bool {
        return self.revoked.contains(certificate_id);
    }

    pub fn getRevocation(self: *Self, certificate_id: []const u8) ?RevocationRecord {
        return self.revoked.get(certificate_id);
    }

    pub fn verify(self: *Self, certificate_id: []const u8) VerificationResult {
        const record = self.certificates.get(certificate_id) orelse {
            return .{ .valid = false, .reason = "Certificate not found on chain" };
        };

        if (record.status == .revoked) {
            return .{ .valid = false, .reason = "Certificate has been revoked" };
        }

        if (record.status == .suspended) {
            return .{ .valid = false, .reason = "Certificate is suspended" };
        }

        if (record.status == .pending) {
            return .{ .valid = false, .reason = "Certificate issuance is pending" };
        }

        if (record.status == .expired) {
            return .{ .valid = false, .reason = "Certificate has expired" };
        }

        return .{ .valid = true, .reason = null };
    }

    pub fn byIssuer(self: *Self, issuer_id: []const u8) []const CertificateRecord {
        var result = std.ArrayList(CertificateRecord).init(self.allocator);
        var iter = self.certificates.valueIterator();
        while (iter.next()) |record| {
            if (std.mem.eql(u8, record.issuer_id, issuer_id)) {
                result.append(record.*) catch continue;
            }
        }
        return result.toOwnedSlice() catch &.{};
    }

    pub fn byRecipient(self: *Self, recipient_id: []const u8) []const CertificateRecord {
        var result = std.ArrayList(CertificateRecord).init(self.allocator);
        var iter = self.certificates.valueIterator();
        while (iter.next()) |record| {
            if (std.mem.eql(u8, record.recipient_id, recipient_id)) {
                result.append(record.*) catch continue;
            }
        }
        return result.toOwnedSlice() catch &.{};
    }
};

pub const VerificationResult = struct {
    valid: bool,
    reason: ?[]const u8,
};

pub const Verifier = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    registry: *CertificateRegistry,
    store: *CertificateStore,

    pub fn init(allocator: std.mem.Allocator, registry: *CertificateRegistry, store: *CertificateStore) Self {
        return .{
            .allocator = allocator,
            .registry = registry,
            .store = store,
        };
    }

    pub fn verify(self: *Self, certificate_id: []const u8, _: [public_key_size]u8) !VerificationResult {
        const chain_result = self.registry.verify(certificate_id);
        if (!chain_result.valid) {
            return chain_result;
        }

        if (self.store.gateway.base_url.len == 0) {
            return .{ .valid = true, .reason = null };
        }

        return .{ .valid = true, .reason = null };
    }

    pub fn verifyFromIPFS(self: *Self, cid_str: []const u8, _: [public_key_size]u8) !VerificationResult {
        const data = self.store.fetch(cid_str) catch {
            return .{ .valid = false, .reason = "Failed to fetch from IPFS" };
        };
        defer self.allocator.free(data);

        return .{ .valid = true, .reason = null };
    }
};

fn generateUuid(allocator: std.mem.Allocator) ![]u8 {
    return try std.fmt.allocPrint(allocator, "urn:uuid:{s}", .{
        &std.fmt.bytesToHex(std.crypto.random.bytes([16]u8), .lower),
    });
}

pub fn createEducational(
    allocator: std.mem.Allocator,
    issuer: Issuer,
    recipient: Recipient,
    cert_name: []const u8,
    description: []const u8,
    issued: u64,
    valid_until: ?u64,
) !CertificateMetadata {
    const cert_id = try generateUuid(allocator);
    errdefer allocator.free(cert_id);

    const subject_id = try generateUuid(allocator);
    errdefer allocator.free(subject_id);

    const cred_subject_id = try generateUuid(allocator);
    errdefer allocator.free(cred_subject_id);

    return CertificateMetadata{
        .@"@context" = "https://w3id.org/openbadges/v3",
        .type = "Assertion",
        .id = cert_id,
        .name = cert_name,
        .description = description,
        .encoding = "base64",
        .audience = null,
        .subject = .{
            .id = subject_id,
            .name = recipient.name,
            .alternate_name = null,
            .description = null,
            .url = null,
            .skills = null,
            .occupation = null,
            .additional_properties = null,
        },
        .issued = issued,
        .valid_from = issued,
        .valid_until = valid_until,
        .issuer = issuer,
        .credential_subject = .{
            .id = cred_subject_id,
            .name = recipient.name,
            .alternate_name = null,
            .description = null,
            .url = null,
            .skills = null,
            .occupation = null,
            .additional_properties = null,
        },
        .evidence = null,
        .endorsements = null,
        .is_child_of = null,
        .is_wholed_for = null,
        .has_part = null,
        .aligns_with = null,
        .related = null,
        .attachments = null,
    };
}

pub fn createProfessional(
    allocator: std.mem.Allocator,
    issuer: Issuer,
    recipient: Recipient,
    cert_name: []const u8,
    description: []const u8,
    issued: u64,
    valid_until: ?u64,
    skills: [][]const u8,
) !CertificateMetadata {
    var cert = try createEducational(
        allocator,
        issuer,
        recipient,
        cert_name,
        description,
        issued,
        valid_until,
    );
    errdefer allocator.free(cert.subject.id);
    errdefer allocator.free(cert.credential_subject.id);

    cert.subject.skills = skills;

    return cert;
}

pub fn createTraining(
    allocator: std.mem.Allocator,
    issuer: Issuer,
    recipient: Recipient,
    course_name: []const u8,
    description: []const u8,
    hours_completed: u32,
    issued: u64,
) !CertificateMetadata {
    const cert_id = try generateUuid(allocator);
    errdefer allocator.free(cert_id);

    const subject_id = try generateUuid(allocator);
    errdefer allocator.free(subject_id);

    const cred_subject_id = try generateUuid(allocator);
    errdefer allocator.free(cred_subject_id);

    return CertificateMetadata{
        .@"@context" = "https://w3id.org/openbadges/v3",
        .type = "Assertion",
        .id = cert_id,
        .name = course_name,
        .description = try std.fmt.allocPrint(allocator, "{s} - {d} hours", .{ description, hours_completed }),
        .encoding = "base64",
        .audience = null,
        .subject = .{
            .id = subject_id,
            .name = recipient.name,
            .alternate_name = null,
            .description = null,
            .url = null,
            .skills = null,
            .occupation = null,
            .additional_properties = null,
        },
        .issued = issued,
        .valid_from = issued,
        .valid_until = null,
        .issuer = issuer,
        .credential_subject = .{
            .id = cred_subject_id,
            .name = recipient.name,
            .alternate_name = null,
            .description = null,
            .url = null,
            .skills = null,
            .occupation = null,
            .additional_properties = null,
        },
        .evidence = null,
        .endorsements = null,
        .is_child_of = null,
        .is_wholed_for = null,
        .has_part = null,
        .aligns_with = null,
        .related = null,
        .attachments = null,
    };
}

pub fn createLicense(
    allocator: std.mem.Allocator,
    issuer: Issuer,
    recipient: Recipient,
    license_type: []const u8,
    license_number: []const u8,
    issued: u64,
    valid_until: u64,
) !CertificateMetadata {
    const cert_id = try generateUuid(allocator);
    errdefer allocator.free(cert_id);

    const subject_id = try generateUuid(allocator);
    errdefer allocator.free(subject_id);

    const cred_subject_id = try generateUuid(allocator);
    errdefer allocator.free(cred_subject_id);

    return CertificateMetadata{
        .@"@context" = "https://w3id.org/openbadges/v3",
        .type = "Assertion",
        .id = cert_id,
        .name = license_type,
        .description = try std.fmt.allocPrint(allocator, "License #{s}", .{license_number}),
        .encoding = "base64",
        .audience = null,
        .subject = .{
            .id = subject_id,
            .name = recipient.name,
            .alternate_name = null,
            .description = null,
            .url = null,
            .skills = null,
            .occupation = null,
            .additional_properties = null,
        },
        .issued = issued,
        .valid_from = issued,
        .valid_until = valid_until,
        .issuer = issuer,
        .credential_subject = .{
            .id = cred_subject_id,
            .name = recipient.name,
            .alternate_name = null,
            .description = null,
            .url = null,
            .skills = null,
            .occupation = null,
            .additional_properties = null,
        },
        .evidence = null,
        .endorsements = null,
        .is_child_of = null,
        .is_wholed_for = null,
        .has_part = null,
        .aligns_with = null,
        .related = null,
        .attachments = null,
    };
}

test "CertificateType enum values" {
    try std.testing.expect(@intFromEnum(CertificateType.educational) == 0);
    try std.testing.expect(@intFromEnum(CertificateType.professional) == 1);
    try std.testing.expect(@intFromEnum(CertificateType.vocational) == 2);
    try std.testing.expect(@intFromEnum(CertificateType.skills_badge) == 3);
    try std.testing.expect(@intFromEnum(CertificateType.employment) == 4);
    try std.testing.expect(@intFromEnum(CertificateType.training) == 5);
    try std.testing.expect(@intFromEnum(CertificateType.license) == 6);
    try std.testing.expect(@intFromEnum(CertificateType.membership) == 7);
    try std.testing.expect(@intFromEnum(CertificateType.award) == 8);
    try std.testing.expect(@intFromEnum(CertificateType.custom) == 9);
}

test "VerificationStatus enum values" {
    try std.testing.expect(@intFromEnum(VerificationStatus.valid) == 0);
    try std.testing.expect(@intFromEnum(VerificationStatus.revoked) == 1);
    try std.testing.expect(@intFromEnum(VerificationStatus.expired) == 2);
    try std.testing.expect(@intFromEnum(VerificationStatus.suspended) == 3);
    try std.testing.expect(@intFromEnum(VerificationStatus.pending) == 4);
}

test "CertificateStore initialization" {
    const allocator = std.testing.allocator;
    var store = CertificateStore.init(allocator, "https://cloudflare-ipfs.com");
    defer store.deinit();
    try std.testing.expect(store.allocator == allocator);
}

test "Certificate revoke" {
    const allocator = std.testing.allocator;
    var cert = Certificate{
        .id = "cert-123",
        .issuer = .{ .id = "issuer-1", .name = "Test Issuer", .public_key = [_]u8{0} ** 32 },
        .recipient = .{ .id = "recipient-1", .name = "John Doe", .public_key = [_]u8{0} ** 32 },
        .certificate_type = .educational,
        .metadata = .{
            .@"@context" = "",
            .type = "",
            .id = "cert-123",
            .name = "Test Cert",
            .description = null,
            .encoding = "",
            .audience = null,
            .subject = .{ .id = "subj-1", .name = "John" },
            .issued = 0,
            .valid_from = 0,
            .valid_until = null,
            .issuer = undefined,
            .credential_subject = undefined,
            .evidence = null,
            .endorsements = null,
            .is_child_of = null,
            .is_wholed_for = null,
            .has_part = null,
            .aligns_with = null,
            .related = null,
            .attachments = null,
        },
        .verification_status = .valid,
        .ipfs_cid = null,
        .attachments_cid = null,
        .issued_at = 0,
        .revoked_at = null,
        .revoke_reason = null,
        .signature = [_]u8{0} ** 64,
        .blockchain_tx_hash = null,
    };

    try std.testing.expect(cert.verification_status == .valid);
    cert.revoke("Fraudulent certificate");
    try std.testing.expect(cert.verification_status == .revoked);
    try std.testing.expect(cert.revoked_at != null);
    try std.testing.expect(cert.revoke_reason != null);
    _ = allocator;
}

test "Certificate suspend and reactivate" {
    var cert = Certificate{
        .id = "cert-456",
        .issuer = .{ .id = "issuer-1", .name = "Test Issuer", .public_key = [_]u8{0} ** 32 },
        .recipient = .{ .id = "recipient-1", .name = "John Doe", .public_key = [_]u8{0} ** 32 },
        .certificate_type = .professional,
        .metadata = .{
            .@"@context" = "",
            .type = "",
            .id = "cert-456",
            .name = "Test Cert",
            .description = null,
            .encoding = "",
            .audience = null,
            .subject = .{ .id = "subj-1", .name = "John" },
            .issued = 0,
            .valid_from = 0,
            .valid_until = null,
            .issuer = undefined,
            .credential_subject = undefined,
            .evidence = null,
            .endorsements = null,
            .is_child_of = null,
            .is_wholed_for = null,
            .has_part = null,
            .aligns_with = null,
            .related = null,
            .attachments = null,
        },
        .verification_status = .valid,
        .ipfs_cid = null,
        .attachments_cid = null,
        .issued_at = 0,
        .revoked_at = null,
        .revoke_reason = null,
        .signature = [_]u8{0} ** 64,
        .blockchain_tx_hash = null,
    };

    cert.markSuspended();
    try std.testing.expect(cert.verification_status == .suspended);

    cert.markActive();
    try std.testing.expect(cert.verification_status == .valid);
}

test "CertificateRegistry register and verify" {
    const allocator = std.testing.allocator;
    var registry = CertificateRegistry.init(allocator);
    defer registry.deinit();

    const record = CertificateRegistry.CertificateRecord{
        .id = "cert-789",
        .issuer_id = "issuer-1",
        .recipient_id = "recipient-1",
        .status = .valid,
        .ipfs_cid = null,
        .tx_hash = "tx-hash-123",
        .issued_at = 0,
        .revoked_at = null,
    };

    try registry.register(record);

    const result = registry.verify("cert-789");
    try std.testing.expect(result.valid);

    const not_found = registry.verify("cert-999");
    try std.testing.expect(!not_found.valid);
}

test "CertificateRegistry revoke" {
    const allocator = std.testing.allocator;
    var registry = CertificateRegistry.init(allocator);
    defer registry.deinit();

    const record = CertificateRegistry.CertificateRecord{
        .id = "cert-revoke-test",
        .issuer_id = "issuer-1",
        .recipient_id = "recipient-1",
        .status = .valid,
        .ipfs_cid = null,
        .tx_hash = "tx-hash",
        .issued_at = 0,
        .revoked_at = null,
    };

    try registry.register(record);
    try registry.revoke("cert-revoke-test", "Key compromise", "issuer-1");

    const result = registry.verify("cert-revoke-test");
    try std.testing.expect(!result.valid);
    try std.testing.expect(registry.isRevoked("cert-revoke-test"));

    const revocation = registry.getRevocation("cert-revoke-test");
    try std.testing.expect(revocation != null);
}

test "VerificationResult structure" {
    const result = VerificationResult{ .valid = true, .reason = null };
    try std.testing.expect(result.valid);
    try std.testing.expect(result.reason == null);

    const failed = VerificationResult{ .valid = false, .reason = "Not found" };
    try std.testing.expect(!failed.valid);
    try std.testing.expect(failed.reason != null);
}
