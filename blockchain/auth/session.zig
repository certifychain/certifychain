const std = @import("std");

pub const session_id_len = 32;
pub const session_timeout: u64 = 3600;

pub const Session = struct {
    id: [session_id_len]u8,
    identity_id: []const u8,
    created_at: u64,
    expires_at: u64,
    last_activity: u64,
    ip_address: ?[]const u8,
    user_agent: ?[]const u8,
};

pub const SessionStore = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    sessions: std.StringHashMap(Session),

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .sessions = std.StringHashMap(Session).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.identity_id);
        }
        self.sessions.deinit();
    }

    pub fn create(
        self: *Self,
        identity_id: []const u8,
        ip_address: ?[]const u8,
        user_agent: ?[]const u8,
    ) !Session {
        var id: [session_id_len]u8 = undefined;
        std.crypto.random.bytes(&id);

        const now = @as(u64, @intCast(std.time.timestamp()));
        const session = Session{
            .id = id,
            .identity_id = try self.allocator.dupe(u8, identity_id),
            .created_at = now,
            .expires_at = now + session_timeout,
            .last_activity = now,
            .ip_address = if (ip_address) |ip| try self.allocator.dupe(u8, ip) else null,
            .user_agent = if (user_agent) |ua| try self.allocator.dupe(u8, ua) else null,
        };

        const key = std.fmt.bytesToHex(&id, .lower);
        try self.sessions.put(try self.allocator.dupe(u8, &key), session);
        return session;
    }

    pub fn get(self: *Self, id: [session_id_len]u8) ?Session {
        const key = std.fmt.bytesToHex(&id, .lower);
        return self.sessions.get(&key);
    }

    pub fn valid(self: *Self, id: [session_id_len]u8) bool {
        const session = self.get(id) orelse return false;
        const now = @as(u64, @intCast(std.time.timestamp()));
        return now < session.expires_at;
    }

    pub fn refresh(self: *Self, id: [session_id_len]u8) void {
        const key = std.fmt.bytesToHex(&id, .lower);
        if (self.sessions.getPtr(&key)) |session| {
            const now = @as(u64, @intCast(std.time.timestamp()));
            session.last_activity = now;
            session.expires_at = now + session_timeout;
        }
    }

    pub fn revoke(self: *Self, id: [session_id_len]u8) void {
        const key = std.fmt.bytesToHex(&id, .lower);
        if (self.sessions.fetchRemove(&key)) |entry| {
            self.allocator.free(entry.key);
            self.allocator.free(entry.value.identity_id);
        }
    }

    pub fn revokeAll(self: *Self, identity_id: []const u8) void {
        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            if (std.mem.eql(u8, entry.value_ptr.identity_id, identity_id)) {
                self.revoke(entry.value_ptr.id);
            }
        }
    }

    pub fn cleanup(self: *Self) void {
        const now = @as(u64, @intCast(std.time.timestamp()));
        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            if (now >= entry.value_ptr.expires_at) {
                self.revoke(entry.value_ptr.id);
            }
        }
    }
};

pub fn generateSessionId() [session_id_len]u8 {
    var id: [session_id_len]u8 = undefined;
    std.crypto.random.bytes(&id);
    return id;
}

test "SessionStore init" {
    const allocator = std.testing.allocator;
    var store = SessionStore.init(allocator);
    defer store.deinit();
    try std.testing.expect(store.sessions.count() == 0);
}

test "SessionStore create/get" {
    const allocator = std.testing.allocator;
    var store = SessionStore.init(allocator);
    defer store.deinit();

    const session = try store.create("user-123", null, null);
    try std.testing.expect(store.sessions.count() == 1);
    try std.testing.expect(store.get(session.id) != null);
}

test "SessionStore valid/revoke" {
    const allocator = std.testing.allocator;
    var store = SessionStore.init(allocator);
    defer store.deinit();

    const session = try store.create("user-123", null, null);
    try std.testing.expect(store.valid(session.id));

    store.revoke(session.id);
    try std.testing.expect(!store.valid(session.id));
}

test "generateSessionId" {
    const a = generateSessionId();
    const b = generateSessionId();
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
}
