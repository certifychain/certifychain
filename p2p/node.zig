const std = @import("std");
const peer = @import("peer.zig");
const address = @import("address.zig");
const state = @import("state.zig");
const database = @import("database.zig");
const message = @import("message.zig");
const blockchain = @import("blockchain");

pub const NodeId = peer.NodeId;
pub const PeerId = peer.PeerId;
pub const Address = address.Address;
pub const Peer = state.Peer;
pub const ConnectionState = state.ConnectionState;
pub const PeerDatabase = database.PeerDatabase;
pub const MessageType = message.MessageType;
pub const Message = message.Message;

pub const Node = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    node_id: NodeId,
    peer_db: PeerDatabase,
    address: Address,
    server: ?std.net.Server,
    registry: ?*blockchain.CertificateRegistry,

    pub fn init(allocator: std.mem.Allocator, port: u16) !Self {
        var seed: [32]u8 = undefined;
        std.crypto.random.bytes(&seed);
        const node_id = blockchain.hash.hashData(&seed);

        const addr = Address{
            .ip = "0.0.0.0",
            .port = port,
            .peer_id = node_id,
        };

        var peer_db = PeerDatabase.init(allocator);
        errdefer peer_db.deinit();

        return .{
            .allocator = allocator,
            .node_id = node_id,
            .peer_db = peer_db,
            .address = addr,
            .server = null,
            .registry = null,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.server) |*s| {
            s.deinit();
        }
        self.peer_db.deinit();
    }

    pub fn start(self: *Self) !void {
        self.server = std.net.Server.listen(
            std.net.Address.parseIp4(self.address.ip, self.address.port) catch return error.InvalidAddress,
            128,
        ) catch return error.FailedToStartServer;
    }

    pub fn setRegistry(self: *Self, registry: *blockchain.CertificateRegistry) void {
        self.registry = registry;
    }

    pub fn broadcastTransaction(self: *Self, _: blockchain.Transaction) !void {
        const active_peers = self.peer_db.activePeers();
        defer self.allocator.free(active_peers);

        for (active_peers) |_| {}
    }

    pub fn handleIncomingConnection(_: *Self, conn: std.net.Server.Connection) !void {
        defer conn.stream.close();
        var buf: [4096]u8 = undefined;
        const bytes_read = conn.stream.reader().read(&buf) catch return;
        if (bytes_read == 0) return;

        const msg_type: MessageType = @enumFromInt(buf[0]);
        _ = msg_type;
    }

    pub fn queryCertificate(self: *Self, certificate_id: []const u8) blockchain.VerificationResult {
        if (self.registry) |reg| {
            return reg.verify(certificate_id);
        }
        return .{ .valid = false, .reason = "Registry not configured" };
    }

    pub fn broadcastVerificationQuery(self: *Self, certificate_id: []const u8, requester: PeerId) !void {
        const msg = Message.create(.certificate_query, certificate_id);
        _ = msg;
        _ = requester;
        const active_peers = self.peer_db.activePeers();
        defer self.allocator.free(active_peers);

        for (active_peers) |_| {}
    }

    pub fn handleVerificationRequest(self: *Self, certificate_id: []const u8) blockchain.VerificationResult {
        return self.queryCertificate(certificate_id);
    }

    pub fn broadcastRevocation(self: *Self, certificate_id: []const u8, reason: []const u8) !void {
        _ = certificate_id;
        _ = reason;
        const active_peers = self.peer_db.activePeers();
        defer self.allocator.free(active_peers);

        for (active_peers) |_| {}
    }
};

pub const NetworkVerifier = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    registry: blockchain.CertificateRegistry,
    node: ?*Node,
    min_verifications: u8 = 3,

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .registry = blockchain.CertificateRegistry.init(allocator),
            .node = null,
            .min_verifications = 3,
        };
    }

    pub fn deinit(self: *Self) void {
        self.registry.deinit();
    }

    pub fn setNode(self: *Self, node: *Node) void {
        self.node = node;
        node.setRegistry(&self.registry);
    }

    pub fn verify(self: *Self, certificate_id: []const u8) blockchain.VerificationResult {
        return self.registry.verify(certificate_id);
    }

    pub fn verifyNetwork(self: *Self, certificate_id: []const u8) !blockchain.VerificationResult {
        const local_result = self.registry.verify(certificate_id);
        if (!local_result.valid) {
            return local_result;
        }

        if (self.node) |n| {
            return n.handleVerificationRequest(certificate_id);
        }

        return local_result;
    }

    pub fn registerCertificate(self: *Self, record: blockchain.CertificateRegistry.CertificateRecord) !void {
        try self.registry.register(record);
    }

    pub fn revokeCertificate(self: *Self, certificate_id: []const u8, reason: []const u8, revoked_by: []const u8) !void {
        try self.registry.revoke(certificate_id, reason, revoked_by);

        if (self.node) |n| {
            n.broadcastRevocation(certificate_id, reason) catch {};
        }
    }
};

pub fn generateNodeId(_: std.mem.Allocator) !NodeId {
    var seed: [32]u8 = undefined;
    std.crypto.random.bytes(&seed);
    return blockchain.hash.hashData(&seed);
}

pub fn createPeerId() PeerId {
    var id: PeerId = undefined;
    std.crypto.random.bytes(&id);
    return id;
}

test "NodeId generation" {
    const allocator = std.testing.allocator;
    const id1 = try generateNodeId(allocator);
    const id2 = try generateNodeId(allocator);
    try std.testing.expect(!std.mem.eql(u8, &id1, &id2));
}

test "PeerId generation" {
    const id1 = createPeerId();
    const id2 = createPeerId();
    try std.testing.expect(!std.mem.eql(u8, &id1, &id2));
}

test "ConnectionState values" {
    try std.testing.expect(@intFromEnum(ConnectionState.disconnected) == 0);
    try std.testing.expect(@intFromEnum(ConnectionState.active) == 4);
}

test "MessageType enum values" {
    try std.testing.expect(@intFromEnum(MessageType.handshake) == 0x01);
    try std.testing.expect(@intFromEnum(MessageType.transaction) == 0x10);
    try std.testing.expect(@intFromEnum(MessageType.certificate_validation) == 0x42);
}

test "NetworkVerifier initialization" {
    const allocator = std.testing.allocator;
    var verifier = NetworkVerifier.init(allocator);
    defer verifier.deinit();
    try std.testing.expect(verifier.min_verifications == 3);
}

test "NetworkVerifier register and verify" {
    const allocator = std.testing.allocator;
    var verifier = NetworkVerifier.init(allocator);
    defer verifier.deinit();

    const record = blockchain.CertificateRegistry.CertificateRecord{
        .id = "net-cert-1",
        .issuer_id = "issuer-1",
        .recipient_id = "recipient-1",
        .status = .valid,
        .ipfs_cid = null,
        .tx_hash = "tx-hash",
        .issued_at = 0,
        .revoked_at = null,
    };

    try verifier.registerCertificate(record);
    const result = verifier.verify("net-cert-1");
    try std.testing.expect(result.valid);
}

test "NetworkVerifier revoke" {
    const allocator = std.testing.allocator;
    var verifier = NetworkVerifier.init(allocator);
    defer verifier.deinit();

    const record = blockchain.CertificateRegistry.CertificateRecord{
        .id = "net-cert-2",
        .issuer_id = "issuer-1",
        .recipient_id = "recipient-1",
        .status = .valid,
        .ipfs_cid = null,
        .tx_hash = "tx-hash",
        .issued_at = 0,
        .revoked_at = null,
    };

    try verifier.registerCertificate(record);
    try verifier.revokeCertificate("net-cert-2", "Key compromise", "issuer-1");

    const result = verifier.verify("net-cert-2");
    try std.testing.expect(!result.valid);
}
