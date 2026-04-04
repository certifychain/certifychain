const std = @import("std");
const signature = @import("../signature.zig");
const hash = @import("../hash.zig");

pub const PUBLIC_KEY_SIZE = signature.PUBLIC_KEY_SIZE;

pub const Identity = struct {
    id: []const u8,
    public_key: [PUBLIC_KEY_SIZE]u8,
    created_at: u64,
    last_authenticated: ?u64,
    trusted: bool,
    metadata: ?[]const u8,
};

pub const IdentityStore = struct {
    allocator: std.mem.Allocator,
    identities: std.StringHashMap(Identity),

    pub fn init(allocator: std.mem.Allocator) IdentityStore {
        return .{
            .allocator = allocator,
            .identities = std.StringHashMap(Identity).init(allocator),
        };
    }

    pub fn deinit(self: *IdentityStore) void {
        var it = self.identities.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.identities.deinit();
    }

    pub fn createIdentity(
        self: *IdentityStore,
        public_key: [PUBLIC_KEY_SIZE]u8,
        metadata: ?[]const u8,
    ) ![]const u8 {
        const id = try self.generateIdentityId(public_key);
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

    pub fn getIdentity(self: *IdentityStore, id: []const u8) ?Identity {
        return self.identities.get(id);
    }

    pub fn getIdentityByPublicKey(self: *IdentityStore, public_key: [PUBLIC_KEY_SIZE]u8) ?Identity {
        var it = self.identities.valueIterator();
        while (it.next()) |identity| {
            if (std.mem.eql(u8, &identity.public_key, &public_key)) {
                return identity.*;
            }
        }
        return null;
    }

    pub fn trustIdentity(self: *IdentityStore, id: []const u8) !void {
        if (self.identities.getPtr(id)) |identity| {
            identity.trusted = true;
        }
    }

    pub fn updateLastAuth(self: *IdentityStore, id: []const u8) !void {
        if (self.identities.getPtr(id)) |identity| {
            identity.last_authenticated = @as(u64, @intCast(std.time.timestamp()));
        }
    }

    fn generateIdentityId(self: *IdentityStore, public_key: [PUBLIC_KEY_SIZE]u8) ![]u8 {
        const timestamp = @as(u64, @intCast(std.time.timestamp()));
        var data: [PUBLIC_KEY_SIZE + 8]u8 = undefined;
        @memcpy(data[0..PUBLIC_KEY_SIZE], &public_key);
        std.mem.writeInt(u64, data[PUBLIC_KEY_SIZE..][0..8], timestamp, .big);
        const hash_val = hash.hashData(&data);
        return try std.fmt.allocPrint(self.allocator, "ID:{s}", .{
            &std.fmt.bytesToHex(hash_val[0..16], .lower),
        });
    }
};

pub fn generateKeyPair() signature.KeyPair {
    return signature.generateKeyPair();
}

pub fn publicKeyToBytes(key: signature.PublicKey) [PUBLIC_KEY_SIZE]u8 {
    return key.toBytes();
}

pub fn publicKeyFromBytes(bytes: [PUBLIC_KEY_SIZE]u8) !signature.PublicKey {
    return signature.PublicKey.fromBytes(bytes);
}

test "IdentityStore initialization" {
    const allocator = std.testing.allocator;
    var store = IdentityStore.init(allocator);
    defer store.deinit();
    try std.testing.expect(store.identities.count() == 0);
}

test "IdentityStore create/get identity" {
    const allocator = std.testing.allocator;
    var store = IdentityStore.init(allocator);
    defer store.deinit();

    const keypair = generateKeyPair();
    const id = try store.createIdentity(keypair.public_key.bytes, null);
    defer allocator.free(id);

    try std.testing.expect(store.identities.count() == 1);
    const identity = store.getIdentity(id);
    try std.testing.expect(identity != null);
    try std.testing.expect(identity.?.trusted == false);
}

test "IdentityStore trust identity" {
    const allocator = std.testing.allocator;
    var store = IdentityStore.init(allocator);
    defer store.deinit();

    const keypair = generateKeyPair();
    const id = try store.createIdentity(keypair.public_key.bytes, null);
    defer allocator.free(id);

    try store.trustIdentity(id);
    const identity = store.getIdentity(id);
    try std.testing.expect(identity.?.trusted == true);
}

test "publicKeyToBytes/FromBytes roundtrip" {
    const keypair = generateKeyPair();
    const bytes = publicKeyToBytes(keypair.public_key);
    const reconstructed = try publicKeyFromBytes(bytes);
    try std.testing.expect(std.mem.eql(u8, &keypair.public_key.bytes, &reconstructed.bytes));
}
