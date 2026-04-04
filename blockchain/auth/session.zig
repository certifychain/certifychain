const std = @import("std");
const hash = @import("../hash.zig");

pub const SESSION_ID_SIZE = 32;
pub const SESSION_TIMEOUT_SECONDS: u64 = 3600;

pub const Session = struct {
    id: [SESSION_ID_SIZE]u8,
    identity_id: []const u8,
    created_at: u64,
    expires_at: u64,
    last_activity: u64,
    ip_address: ?[]const u8,
    user_agent: ?[]const u8,
};

pub const SessionStore = struct {
    allocator: std.mem.Allocator,
    sessions: std.StringHashMap(Session),

    pub fn init(allocator: std.mem.Allocator) SessionStore {
        return .{
            .allocator = allocator,
            .sessions = std.StringHashMap(Session).init(allocator),
        };
    }

    pub fn deinit(self: *SessionStore) void {
        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.identity_id);
        }
        self.sessions.deinit();
    }

    pub fn createSession(
        self: *SessionStore,
        identity_id: []const u8,
        ip_address: ?[]const u8,
        user_agent: ?[]const u8,
    ) !Session {
        var session_id: [SESSION_ID_SIZE]u8 = undefined;
        std.crypto.random.bytes(&session_id);

        const now = @as(u64, @intCast(std.time.timestamp()));
        const session = Session{
            .id = session_id,
            .identity_id = try self.allocator.dupe(u8, identity_id),
            .created_at = now,
            .expires_at = now + SESSION_TIMEOUT_SECONDS,
            .last_activity = now,
            .ip_address = if (ip_address) |ip| try self.allocator.dupe(u8, ip) else null,
            .user_agent = if (user_agent) |ua| try self.allocator.dupe(u8, ua) else null,
        };

        const key = std.fmt.bytesToHex(&session_id, .lower);
        try self.sessions.put(try self.allocator.dupe(u8, &key), session);
        return session;
    }

    pub fn getSession(self: *SessionStore, session_id: [SESSION_ID_SIZE]u8) ?Session {
        const key = std.fmt.bytesToHex(&session_id, .lower);
        return self.sessions.get(&key);
    }

    pub fn validateSession(self: *SessionStore, session_id: [SESSION_ID_SIZE]u8) bool {
        const session = self.getSession(session_id) orelse return false;
        const now = @as(u64, @intCast(std.time.timestamp()));
        return now < session.expires_at;
    }

    pub fn refreshSession(self: *SessionStore, session_id: [SESSION_ID_SIZE]u8) !void {
        const key = std.fmt.bytesToHex(&session_id, .lower);
        if (self.sessions.getPtr(&key)) |session| {
            const now = @as(u64, @intCast(std.time.timestamp()));
            session.last_activity = now;
            session.expires_at = now + SESSION_TIMEOUT_SECONDS;
        }
    }

    pub fn revokeSession(self: *SessionStore, session_id: [SESSION_ID_SIZE]u8) void {
        const key = std.fmt.bytesToHex(&session_id, .lower);
        if (self.sessions.fetchRemove(&key)) |entry| {
            self.allocator.free(entry.key);
            self.allocator.free(entry.value.identity_id);
        }
    }

    pub fn revokeAllSessions(self: *SessionStore, identity_id: []const u8) void {
        var to_remove = std.ArrayList([SESSION_ID_SIZE]u8).init(self.allocator);
        defer to_remove.deinit();

        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            if (std.mem.eql(u8, entry.value_ptr.identity_id, identity_id)) {
                const session_id = std.fmt.hexToBytes(&[_]u8{0} ** SESSION_ID_SIZE) catch continue;
                to_remove.append(session_id) catch continue;
            }
        }

        for (to_remove.items) |session_id| {
            self.revokeSession(session_id);
        }
    }

    pub fn cleanupExpired(self: *SessionStore) void {
        const now = @as(u64, @intCast(std.time.timestamp()));
        var to_remove = std.ArrayList([SESSION_ID_SIZE]u8).init(self.allocator);
        defer to_remove.deinit();

        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            if (now >= entry.value_ptr.expires_at) {
                const session_id = std.fmt.hexToBytes(&[_]u8{0} ** SESSION_ID_SIZE) catch continue;
                to_remove.append(session_id) catch continue;
            }
        }

        for (to_remove.items) |session_id| {
            self.revokeSession(session_id);
        }
    }
};

pub fn generateSessionId() [SESSION_ID_SIZE]u8 {
    var id: [SESSION_ID_SIZE]u8 = undefined;
    std.crypto.random.bytes(&id);
    return id;
}

test "SessionStore initialization" {
    const allocator = std.testing.allocator;
    var store = SessionStore.init(allocator);
    defer store.deinit();
    try std.testing.expect(store.sessions.count() == 0);
}

test "SessionStore create/get session" {
    const allocator = std.testing.allocator;
    var store = SessionStore.init(allocator);
    defer store.deinit();

    const session = try store.createSession("test-identity", null, null);
    try std.testing.expect(store.sessions.count() == 1);

    const retrieved = store.getSession(session.id);
    try std.testing.expect(retrieved != null);
    try std.testing.expect(std.mem.eql(u8, retrieved.?.identity_id, "test-identity"));
}

test "SessionStore validate session" {
    const allocator = std.testing.allocator;
    var store = SessionStore.init(allocator);
    defer store.deinit();

    const session = try store.createSession("test-identity", null, null);
    try std.testing.expect(store.validateSession(session.id) == true);

    store.revokeSession(session.id);
    try std.testing.expect(store.validateSession(session.id) == false);
}

test "SessionStore refresh session" {
    const allocator = std.testing.allocator;
    var store = SessionStore.init(allocator);
    defer store.deinit();

    const session = try store.createSession("test-identity", null, null);
    const original_expires = session.expires_at;

    std.time.sleep(100);
    try store.refreshSession(session.id);

    const refreshed = store.getSession(session.id);
    try std.testing.expect(refreshed.?.expires_at >= original_expires);
}

test "generateSessionId" {
    const id1 = generateSessionId();
    const id2 = generateSessionId();
    try std.testing.expect(!std.mem.eql(u8, &id1, &id2));
}
