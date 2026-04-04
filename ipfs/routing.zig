const std = @import("std");
const cid_mod = @import("cid.zig");
const multihash = @import("multihash.zig");

pub const Peer = struct {
    id: []const u8,
    addrs: [][]const u8,
};

pub const ProviderRecord = struct {
    cid: cid_mod.CID,
    peers: []Peer,
};

pub const Routing = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Routing {
        return .{ .allocator = allocator };
    }

    pub fn findProviders(self: *Routing, cid: cid_mod.CID) ![]ProviderRecord {
        _ = self;
        _ = cid;
        return &.{};
    }

    pub fn provide(self: *Routing, cid: cid_mod.CID) !void {
        _ = self;
        _ = cid;
    }
};

pub const DelegatedRouting = struct {
    allocator: std.mem.Allocator,
    endpoint: []const u8,
    client: std.http.Client,

    pub fn init(allocator: std.mem.Allocator, endpoint: []const u8) DelegatedRouting {
        return .{
            .allocator = allocator,
            .endpoint = endpoint,
            .client = std.http.Client{ .allocator = allocator },
        };
    }

    pub fn deinit(self: *DelegatedRouting) void {
        self.client.deinit();
    }

    pub fn findProviders(self: *DelegatedRouting, cid_str: []const u8) ![]u8 {
        const url = try std.fmt.allocPrint(self.allocator, "{s}/routing/v1/providers/{s}", .{
            self.endpoint,
            cid_str,
        });
        defer self.allocator.free(url);

        const uri = try std.Uri.parse(url);
        var req = try self.client.open(.GET, uri, .{
            .server_header_buffer = .{ .allocator = self.allocator },
        });
        defer req.deinit();

        try req.send();
        try req.wait();
        return try req.reader().readAllAlloc(self.allocator, std.math.maxInt(usize));
    }
};

pub const IPNS = struct {
    allocator: std.mem.Allocator,

    pub const Record = struct {
        value: []const u8,
        sequence: u64,
        validity: i64,
    };

    pub fn parseRecord(allocator: std.mem.Allocator, data: []const u8) !Record {
        _ = allocator;
        if (data.len < 16) return error.InvalidRecord;
        const seq = std.mem.readInt(u64, data[0..8], .big);
        const validity = std.mem.readInt(i64, data[8..16], .big);
        const value = data[16..];
        return .{
            .value = value,
            .sequence = seq,
            .validity = validity,
        };
    }

    pub fn resolve(allocator: std.mem.Allocator, ipns_name: []const u8, gateway_url: []const u8) ![]u8 {
        const url = try std.fmt.allocPrint(allocator, "{s}/ipns/{s}", .{
            gateway_url,
            ipns_name,
        });
        return url;
    }
};

pub const Kademlia = struct {
    allocator: std.mem.Allocator,
    k: usize = 20,
    alpha: usize = 3,

    pub fn init(allocator: std.mem.Allocator) Kademlia {
        return .{ .allocator = allocator };
    }

    pub fn nodeId(_: *Kademlia, data: []const u8) []const u8 {
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(data, &hash, .{});
        return hash[0..20];
    }

    pub fn distance(_: *Kademlia, a: []const u8, b: []const u8) [20]u8 {
        var result: [20]u8 = undefined;
        for (&result, 0..) |r, i| {
            r.* = a[i] ^ b[i];
        }
        return result;
    }

    pub fn xorClosest(self: *Kademlia, target: []const u8, peers: []Peer) !Peer {
        if (peers.len == 0) return error.NoPeers;
        var closest = peers[0];
        var min_dist = self.distance(target, closest.id);
        for (peers[1..]) |peer| {
            const d = self.distance(target, peer.id);
            for (d, 0..) |b, i| {
                if (b < min_dist[i]) {
                    closest = peer;
                    min_dist = d;
                    break;
                }
            }
        }
        return closest;
    }
};
