const std = @import("std");
const ipfs = @import("ipfs");
const signature = @import("signature.zig");
const hash = @import("hash.zig");

pub const PUBLIC_KEY_SIZE = 32;

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

pub const Issuer = struct {
    id: []const u8,
    name: []const u8,
    public_key: [PUBLIC_KEY_SIZE]u8,
    url: ?[]const u8,
    logo_cid: ?[]const u8,
    description: ?[]const u8,
};

pub const Recipient = struct {
    id: []const u8,
    name: []const u8,
    email: ?[]const u8,
    public_key: [PUBLIC_KEY_SIZE]u8,
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

    pub fn storeMetadata(self: *CertificateStore, metadata: CertificateMetadata) ![]const u8 {
        const json = try self.serializeMetadata(metadata);
        defer self.allocator.free(json);

        const mh = try ipfs.multihash.createMultihash(self.allocator, json, .sha2_256);
        defer self.allocator.free(mh.digest);
        const cid = ipfs.CID.v1(.dag_json, mh);
        return try cid.toString(self.allocator);
    }

    pub fn storeFile(self: *CertificateStore, file_data: []const u8) ![]const u8 {
        const mh = try ipfs.multihash.createMultihash(self.allocator, file_data, .sha2_256);
        defer self.allocator.free(mh.digest);
        const cid = ipfs.CID.v1(.raw, mh);
        return try cid.toString(self.allocator);
    }

    pub fn retrieveFromIPFS(self: *CertificateStore, cid_str: []const u8) ![]u8 {
        return try self.gateway.fetch(cid_str);
    }

    pub fn storeCertificate(
        self: *CertificateStore,
        cert: Certificate,
    ) !struct { metadata_cid: []const u8, tx_hash: []const u8 } {
        const metadata_cid = try self.storeMetadata(cert.metadata);
        const tx_hash = try self.storeMetadata(cert.metadata);

        return .{
            .metadata_cid = metadata_cid,
            .tx_hash = tx_hash,
        };
    }

    pub fn generateCertificateId(self: *CertificateStore, issuer_id: []const u8) ![]u8 {
        var random_bytes: [16]u8 = undefined;
        std.crypto.random.bytes(&random_bytes);
        const hex = std.fmt.bytesToHex(random_bytes, .lower);
        return try std.fmt.allocPrint(self.allocator, "CERT-{s}-{s}", .{ issuer_id, &hex });
    }

    fn serializeMetadata(self: *CertificateStore, metadata: CertificateMetadata) ![]u8 {
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

pub fn createEducationalCertificate(
    allocator: std.mem.Allocator,
    issuer: Issuer,
    recipient: Recipient,
    cert_name: []const u8,
    description: []const u8,
    issued: u64,
    valid_until: ?u64,
) !CertificateMetadata {
    const cert_id = try std.fmt.allocPrint(allocator, "urn:uuid:{s}", .{
        &std.fmt.bytesToHex(std.crypto.random.bytes([16]u8), .lower),
    });
    errdefer allocator.free(cert_id);

    return CertificateMetadata{
        .@"@context" = "https://w3id.org/openbadges/v3",
        .type = "Assertion",
        .id = cert_id,
        .name = cert_name,
        .description = description,
        .encoding = "base64",
        .audience = null,
        .subject = .{
            .id = try std.fmt.allocPrint(allocator, "urn:uuid:{s}", .{
                &std.fmt.bytesToHex(std.crypto.random.bytes([16]u8), .lower),
            }),
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
            .id = try std.fmt.allocPrint(allocator, "urn:uuid:{s}", .{
                &std.fmt.bytesToHex(std.crypto.random.bytes([16]u8), .lower),
            }),
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

pub fn createProfessionalCertificate(
    allocator: std.mem.Allocator,
    issuer: Issuer,
    recipient: Recipient,
    cert_name: []const u8,
    description: []const u8,
    issued: u64,
    valid_until: ?u64,
    skills: [][]const u8,
) !CertificateMetadata {
    var cert = try createEducationalCertificate(
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

pub fn createTrainingCertificate(
    allocator: std.mem.Allocator,
    issuer: Issuer,
    recipient: Recipient,
    course_name: []const u8,
    description: []const u8,
    hours_completed: u32,
    issued: u64,
) !CertificateMetadata {
    const cert_id = try std.fmt.allocPrint(allocator, "urn:uuid:{s}", .{
        &std.fmt.bytesToHex(std.crypto.random.bytes([16]u8), .lower),
    });
    errdefer allocator.free(cert_id);

    return CertificateMetadata{
        .@"@context" = "https://w3id.org/openbadges/v3",
        .type = "Assertion",
        .id = cert_id,
        .name = course_name,
        .description = try std.fmt.allocPrint(allocator, "{s} - {d} hours", .{ description, hours_completed }),
        .encoding = "base64",
        .audience = null,
        .subject = .{
            .id = try std.fmt.allocPrint(allocator, "urn:uuid:{s}", .{
                &std.fmt.bytesToHex(std.crypto.random.bytes([16]u8), .lower),
            }),
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
            .id = try std.fmt.allocPrint(allocator, "urn:uuid:{s}", .{
                &std.fmt.bytesToHex(std.crypto.random.bytes([16]u8), .lower),
            }),
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

pub fn createLicenseCertificate(
    allocator: std.mem.Allocator,
    issuer: Issuer,
    recipient: Recipient,
    license_type: []const u8,
    license_number: []const u8,
    issued: u64,
    valid_until: u64,
) !CertificateMetadata {
    const cert_id = try std.fmt.allocPrint(allocator, "urn:uuid:{s}", .{
        &std.fmt.bytesToHex(std.crypto.random.bytes([16]u8), .lower),
    });
    errdefer allocator.free(cert_id);

    return CertificateMetadata{
        .@"@context" = "https://w3id.org/openbadges/v3",
        .type = "Assertion",
        .id = cert_id,
        .name = license_type,
        .description = try std.fmt.allocPrint(allocator, "License #{s}", .{license_number}),
        .encoding = "base64",
        .audience = null,
        .subject = .{
            .id = try std.fmt.allocPrint(allocator, "urn:uuid:{s}", .{
                &std.fmt.bytesToHex(std.crypto.random.bytes([16]u8), .lower),
            }),
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
            .id = try std.fmt.allocPrint(allocator, "urn:uuid:{s}", .{
                &std.fmt.bytesToHex(std.crypto.random.bytes([16]u8), .lower),
            }),
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

pub fn isExpired(cert: *const Certificate) bool {
    if (cert.metadata.valid_until) |vu| {
        const now = @as(u64, @intCast(std.time.timestamp()));
        return now > vu;
    }
    return false;
}

pub fn isValid(cert: *const Certificate) bool {
    return cert.verification_status == .valid and !isExpired(cert);
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
