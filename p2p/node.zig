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
    allocator: std.mem.Allocator,
    node_id: NodeId,
    peer_db: PeerDatabase,
    address: Address,
    server: ?std.net.Server,

    pub fn init(allocator: std.mem.Allocator, port: u16) !Node {
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
        };
    }

    pub fn deinit(self: *Node) void {
        if (self.server) |*s| {
            s.deinit();
        }
        self.peer_db.deinit();
    }

    pub fn start(self: *Node) !void {
        self.server = std.net.Server.listen(
            std.net.Address.parseIp4(self.address.ip, self.address.port) catch return error.InvalidAddress,
            128,
        ) catch return error.FailedToStartServer;
    }

    pub fn broadcastTransaction(self: *Node, _: blockchain.Transaction) !void {
        const active_peers = self.peer_db.getActivePeers();
        defer self.allocator.free(active_peers);

        for (active_peers) |_| {}
    }

    pub fn handleIncomingConnection(_: *Node, conn: std.net.Server.Connection) !void {
        defer conn.stream.close();
        var buf: [4096]u8 = undefined;
        const bytes_read = conn.stream.reader().read(&buf) catch return;
        if (bytes_read == 0) return;

        const msg_type: MessageType = @enumFromInt(buf[0]);
        _ = msg_type;
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
