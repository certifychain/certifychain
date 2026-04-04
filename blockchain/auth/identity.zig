const std = @import("std");
const sig = @import("../signature.zig");
const h = @import("../hash.zig");

pub const public_key_size = sig.public_key_size;

pub const Identity = struct {
    id: []const u8,
    public_key: [public_key_size]u8,
    created_at: u64,
    last_authenticated: ?u64,
    trusted: bool,
    metadata: ?[]const u8,
};

pub const IdentityStore = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    identities: std.StringHashMap(Identity),

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .identities = std.StringHashMap(Identity).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.identities.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.identities.deinit();
    }

    pub fn create(self: *Self, public_key: [public_key_size]u8, metadata: ?[]const u8) ![]const u8 {
        const id = try self.generateId(public_key);
        const identity = Identity{
            .id = id,
            .public_key = public_key,
            .created_at = @as(u64, @intCast(std.time.timestamp())),
            .last_authenticated = null,
            .trusted = false,
            .metadata = metadata,
        };
        try self.identities.put(id, identity);
        return id;
    }

    pub fn get(self: *Self, id: []const u8) ?Identity {
        return self.identities.get(id);
    }

    pub fn getByPublicKey(self: *Self, public_key: [public_key_size]u8) ?Identity {
        for (self.identities.values()) |identity| {
            if (std.mem.eql(u8, &identity.public_key, &public_key)) {
                return identity;
            }
        }
        return null;
    }

    pub fn trust(self: *Self, id: []const u8) void {
        if (self.identities.getPtr(id)) |identity| {
            identity.trusted = true;
        }
    }

    pub fn updateAuth(self: *Self, id: []const u8) void {
        if (self.identities.getPtr(id)) |identity| {
            identity.last_authenticated = @as(u64, @intCast(std.time.timestamp()));
        }
    }

    fn generateId(self: *Self, public_key: [public_key_size]u8) ![]const u8 {
        const timestamp = @as(u64, @intCast(std.time.timestamp()));
        var data: [public_key_size + 8]u8 = undefined;
        @memcpy(data[0..public_key_size], &public_key);
        std.mem.writeInt(u64, data[public_key_size..][0..8], timestamp, .big);
        const hash_val = h.hash(&data);
        return std.fmt.allocPrint(self.allocator, "ID:{s}", .{
            &std.fmt.bytesToHex(hash_val[0..16], .lower),
        });
    }
};

pub const key_pair = struct {
    pub fn generate() sig.KeyPair {
        return sig.generateKeyPair();
    }
};

pub fn publicKeyToBytes(key: sig.PublicKey) [public_key_size]u8 {
    return key.toBytes();
}

pub fn publicKeyFromBytes(bytes: [public_key_size]u8) !sig.PublicKey {
    return sig.PublicKey.fromBytes(bytes);
}

test "IdentityStore init" {
    const allocator = std.testing.allocator;
    var store = IdentityStore.init(allocator);
    defer store.deinit();
    try std.testing.expect(store.identities.count() == 0);
}

test "IdentityStore create/get" {
    const allocator = std.testing.allocator;
    var store = IdentityStore.init(allocator);
    defer store.deinit();

    const kp = key_pair.generate();
    const id = try store.create(kp.public_key.bytes, null);
    defer allocator.free(id);

    try std.testing.expect(store.identities.count() == 1);
    const identity = store.get(id);
    try std.testing.expect(identity != null);
    try std.testing.expect(!identity.?.trusted);
}

test "IdentityStore trust" {
    const allocator = std.testing.allocator;
    var store = IdentityStore.init(allocator);
    defer store.deinit();

    const kp = key_pair.generate();
    const id = try store.create(kp.public_key.bytes, null);
    defer allocator.free(id);

    store.trust(id);
    try std.testing.expect(store.get(id).?.trusted);
}

test "public key roundtrip" {
    const kp = key_pair.generate();
    const bytes = publicKeyToBytes(kp.public_key);
    const reconstructed = try publicKeyFromBytes(bytes);
    try std.testing.expect(std.mem.eql(u8, &kp.public_key.bytes, &reconstructed.bytes));
}
