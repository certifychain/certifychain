const std = @import("std");
const peer = @import("peer.zig");
const state = @import("state.zig");
const address = @import("address.zig");

pub const PeerId = peer.PeerId;
pub const Peer = state.Peer;
pub const Address = address.Address;

pub const PeerDatabase = struct {
    allocator: std.mem.Allocator,
    peers: std.StringHashMap(Peer),
    bootstrap_nodes: []Address,
    k_bucket_size: usize = 20,

    pub fn init(allocator: std.mem.Allocator) PeerDatabase {
        return .{
            .allocator = allocator,
            .peers = std.StringHashMap(Peer).init(allocator),
            .bootstrap_nodes = &.{},
        };
    }

    pub fn deinit(self: *PeerDatabase) void {
        var it = self.peers.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.peers.deinit();
    }

    pub fn addPeer(self: *PeerDatabase, p: Peer) !void {
        const key = try self.allocator.dupe(u8, &std.fmt.bytesToHex(p.id, .lower));
        try self.peers.put(key, p);
    }

    pub fn removePeer(self: *PeerDatabase, peer_id: PeerId) void {
        const key = std.fmt.bytesToHex(peer_id, .lower);
        if (self.peers.fetchRemove(&key)) |entry| {
            self.allocator.free(entry.key);
        }
    }

    pub fn getPeer(self: *PeerDatabase, peer_id: PeerId) ?Peer {
        const key = std.fmt.bytesToHex(peer_id, .lower);
        return self.peers.get(&key);
    }

    pub fn getActivePeers(self: *PeerDatabase) []Peer {
        var result = std.ArrayList(Peer).init(self.allocator);
        var it = self.peers.valueIterator();
        while (it.next()) |p| {
            if (p.isActive()) {
                result.append(p.*) catch continue;
            }
        }
        return result.toOwnedSlice() catch &.{};
    }

    pub fn getTrustedPeers(self: *PeerDatabase) []Peer {
        var result = std.ArrayList(Peer).init(self.allocator);
        var it = self.peers.valueIterator();
        while (it.next()) |p| {
            if (p.trusted) {
                result.append(p.*) catch continue;
            }
        }
        return result.toOwnedSlice() catch &.{};
    }
};

test "PeerDatabase initialization" {
    const allocator = std.testing.allocator;
    var db = PeerDatabase.init(allocator);
    defer db.deinit();
    try std.testing.expect(db.peers.count() == 0);
}

test "PeerDatabase add/remove peer" {
    const allocator = std.testing.allocator;
    var db = PeerDatabase.init(allocator);
    defer db.deinit();

    const peer_id = blk: {
        var id: PeerId = undefined;
        std.crypto.random.bytes(&id);
        break :blk id;
    };
    const addr_peer_id = blk: {
        var id: PeerId = undefined;
        std.crypto.random.bytes(&id);
        break :blk id;
    };

    const p = Peer{
        .id = peer_id,
        .address = Address{
            .ip = "127.0.0.1",
            .port = 8080,
            .peer_id = addr_peer_id,
        },
        .state = .connected,
        .last_seen = @as(u64, @intCast(std.time.timestamp())),
        .trusted = true,
    };

    try db.addPeer(p);
    try std.testing.expect(db.peers.count() == 1);

    db.removePeer(p.id);
    try std.testing.expect(db.peers.count() == 0);
}
