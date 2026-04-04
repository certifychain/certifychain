const std = @import("std");
const sig = @import("../signature.zig");
const h = @import("../hash.zig");

pub const challenge_len = 32;
pub const challenge_timeout: u64 = 300;

pub const Challenge = struct {
    challenge: [challenge_len]u8,
    identity_id: []const u8,
    created_at: u64,
    expires_at: u64,
    used: bool,
};

pub const ChallengeStore = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    challenges: std.StringHashMap(Challenge),

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .challenges = std.StringHashMap(Challenge).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.challenges.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.identity_id);
        }
        self.challenges.deinit();
    }

    pub fn create(self: *Self, identity_id: []const u8) !Challenge {
        var challenge_bytes: [challenge_len]u8 = undefined;
        std.crypto.random.bytes(&challenge_bytes);

        const now = @as(u64, @intCast(std.time.timestamp()));
        const challenge = Challenge{
            .challenge = challenge_bytes,
            .identity_id = try self.allocator.dupe(u8, identity_id),
            .created_at = now,
            .expires_at = now + challenge_timeout,
            .used = false,
        };

        const key = std.fmt.bytesToHex(&challenge_bytes, .lower);
        try self.challenges.put(try self.allocator.dupe(u8, &key), challenge);
        return challenge;
    }

    pub fn get(self: *Self, challenge_bytes: [challenge_len]u8) ?Challenge {
        const key = std.fmt.bytesToHex(&challenge_bytes, .lower);
        return self.challenges.get(&key);
    }

    pub fn valid(self: *Self, challenge_bytes: [challenge_len]u8) bool {
        const challenge = self.get(challenge_bytes) orelse return false;
        if (challenge.used) return false;
        const now = @as(u64, @intCast(std.time.timestamp()));
        return now < challenge.expires_at;
    }

    pub fn consume(self: *Self, challenge_bytes: [challenge_len]u8) void {
        const key = std.fmt.bytesToHex(&challenge_bytes, .lower);
        if (self.challenges.getPtr(&key)) |challenge| {
            challenge.used = true;
        }
    }

    pub fn cleanup(self: *Self) void {
        const now = @as(u64, @intCast(std.time.timestamp()));
        var it = self.challenges.iterator();
        while (it.next()) |entry| {
            if (now >= entry.value_ptr.expires_at) {
                self.consume(entry.value_ptr.challenge);
            }
        }
    }
};

pub const AuthResult = enum(u8) {
    success,
    invalid_signature,
    expired,
    used,
    invalid_identity,
    unknown,
};

pub const Authenticator = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    store: ChallengeStore,

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .store = ChallengeStore.init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.store.deinit();
    }

    pub fn request(self: *Self, identity_id: []const u8) !Challenge {
        return self.store.create(identity_id);
    }

    pub fn verify(
        self: *Self,
        challenge_bytes: [challenge_len]u8,
        signature_bytes: [sig.signature_size]u8,
        public_key: [sig.public_key_size]u8,
    ) AuthResult {
        if (!self.store.valid(challenge_bytes)) {
            return .expired;
        }

        const challenge = self.store.get(challenge_bytes) orelse return .unknown;
        if (challenge.used) return .used;

        const sig_obj = sig.Signature.fromBytes(signature_bytes);
        const pk = sig.PublicKey.fromBytes(public_key) catch return .invalid_identity;

        const hash_val = h.hash(&challenge_bytes);
        if (!sig.verify(sig_obj, &hash_val, pk)) {
            return .invalid_signature;
        }

        self.store.consume(challenge_bytes);
        return .success;
    }
};

pub fn generateChallenge() [challenge_len]u8 {
    var c: [challenge_len]u8 = undefined;
    std.crypto.random.bytes(&c);
    return c;
}

pub fn signChallenge(challenge: [challenge_len]u8, kp: sig.KeyPair) !sig.Signature {
    const hash_val = h.hash(&challenge);
    return sig.sign(&hash_val, kp);
}

pub fn verifyChallenge(
    challenge: [challenge_len]u8,
    signature_bytes: [sig.signature_size]u8,
    public_key: [sig.public_key_size]u8,
) bool {
    const sig_obj = sig.Signature.fromBytes(signature_bytes);
    const pk = sig.PublicKey.fromBytes(public_key) catch return false;
    const hash_val = h.hash(&challenge);
    return sig.verify(sig_obj, &hash_val, pk);
}

test "ChallengeStore init" {
    const allocator = std.testing.allocator;
    var store = ChallengeStore.init(allocator);
    defer store.deinit();
    try std.testing.expect(store.challenges.count() == 0);
}

test "ChallengeStore create/get" {
    const allocator = std.testing.allocator;
    var store = ChallengeStore.init(allocator);
    defer store.deinit();

    const c = try store.create("user-123");
    try std.testing.expect(store.challenges.count() == 1);
    try std.testing.expect(!store.get(c.challenge).?.used);
}

test "ChallengeStore valid/consume" {
    const allocator = std.testing.allocator;
    var store = ChallengeStore.init(allocator);
    defer store.deinit();

    const c = try store.create("user-123");
    try std.testing.expect(store.valid(c.challenge));

    store.consume(c.challenge);
    try std.testing.expect(!store.valid(c.challenge));
}

test "generateChallenge" {
    const a = generateChallenge();
    const b = generateChallenge();
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
}

test "signChallenge/verifyChallenge" {
    const kp = sig.generateKeyPair();
    const c = generateChallenge();

    const sig_obj = try signChallenge(c, kp);
    const valid = verifyChallenge(c, sig_obj.toBytes(), kp.public_key.bytes);
    try std.testing.expect(valid);
}

test "verifyChallenge rejects wrong key" {
    const kp1 = sig.generateKeyPair();
    const kp2 = sig.generateKeyPair();
    const c = generateChallenge();

    const sig_obj = try signChallenge(c, kp1);
    const valid = verifyChallenge(c, sig_obj.toBytes(), kp2.public_key.bytes);
    try std.testing.expect(!valid);
}
