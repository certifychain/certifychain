const std = @import("std");
const hash = @import("../hash.zig");
const signature = @import("../signature.zig");

pub const CHALLENGE_SIZE = 32;
pub const CHALLENGE_EXPIRY_SECONDS: u64 = 300;

pub const Challenge = struct {
    challenge: [CHALLENGE_SIZE]u8,
    identity_id: []const u8,
    created_at: u64,
    expires_at: u64,
    used: bool,
};

pub const ChallengeStore = struct {
    allocator: std.mem.Allocator,
    challenges: std.StringHashMap(Challenge),

    pub fn init(allocator: std.mem.Allocator) ChallengeStore {
        return .{
            .allocator = allocator,
            .challenges = std.StringHashMap(Challenge).init(allocator),
        };
    }

    pub fn deinit(self: *ChallengeStore) void {
        var it = self.challenges.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.identity_id);
        }
        self.challenges.deinit();
    }

    pub fn createChallenge(self: *ChallengeStore, identity_id: []const u8) !Challenge {
        var challenge_bytes: [CHALLENGE_SIZE]u8 = undefined;
        std.crypto.random.bytes(&challenge_bytes);

        const now = @as(u64, @intCast(std.time.timestamp()));
        const challenge = Challenge{
            .challenge = challenge_bytes,
            .identity_id = try self.allocator.dupe(u8, identity_id),
            .created_at = now,
            .expires_at = now + CHALLENGE_EXPIRY_SECONDS,
            .used = false,
        };

        const key = std.fmt.bytesToHex(&challenge_bytes, .lower);
        try self.challenges.put(try self.allocator.dupe(u8, &key), challenge);
        return challenge;
    }

    pub fn getChallenge(self: *ChallengeStore, challenge_bytes: [CHALLENGE_SIZE]u8) ?Challenge {
        const key = std.fmt.bytesToHex(&challenge_bytes, .lower);
        return self.challenges.get(&key);
    }

    pub fn validateChallenge(self: *ChallengeStore, challenge_bytes: [CHALLENGE_SIZE]u8) bool {
        const challenge = self.getChallenge(challenge_bytes) orelse return false;
        if (challenge.used) return false;
        const now = @as(u64, @intCast(std.time.timestamp()));
        return now < challenge.expires_at;
    }

    pub fn consumeChallenge(self: *ChallengeStore, challenge_bytes: [CHALLENGE_SIZE]u8) !void {
        const key = std.fmt.bytesToHex(&challenge_bytes, .lower);
        if (self.challenges.getPtr(&key)) |challenge| {
            challenge.used = true;
        }
    }

    pub fn cleanupExpired(self: *ChallengeStore) void {
        const now = @as(u64, @intCast(std.time.timestamp()));
        var to_remove = std.ArrayList([CHALLENGE_SIZE]u8).init(self.allocator);
        defer to_remove.deinit();

        var it = self.challenges.iterator();
        while (it.next()) |entry| {
            if (now >= entry.value_ptr.expires_at) {
                const challenge_bytes = std.fmt.hexToBytes(&[_]u8{0} ** CHALLENGE_SIZE) catch continue;
                to_remove.append(challenge_bytes) catch continue;
            }
        }

        for (to_remove.items) |challenge_bytes| {
            const key = std.fmt.bytesToHex(&challenge_bytes, .lower);
            if (self.challenges.fetchRemove(&key)) |entry| {
                self.allocator.free(entry.key);
                self.allocator.free(entry.value.identity_id);
            }
        }
    }
};

pub const AuthenticationResult = enum(u8) {
    success,
    invalid_signature,
    expired_challenge,
    used_challenge,
    invalid_identity,
    unknown_error,
};

pub const ChallengeResponseAuthenticator = struct {
    allocator: std.mem.Allocator,
    challenge_store: ChallengeStore,

    pub fn init(allocator: std.mem.Allocator) ChallengeResponseAuthenticator {
        return .{
            .allocator = allocator,
            .challenge_store = ChallengeStore.init(allocator),
        };
    }

    pub fn deinit(self: *ChallengeResponseAuthenticator) void {
        self.challenge_store.deinit();
    }

    pub fn requestChallenge(self: *ChallengeResponseAuthenticator, identity_id: []const u8) !Challenge {
        return self.challenge_store.createChallenge(identity_id);
    }

    pub fn verifyResponse(
        self: *ChallengeResponseAuthenticator,
        challenge_bytes: [CHALLENGE_SIZE]u8,
        signature_bytes: [signature.SIGNATURE_SIZE]u8,
        public_key: [signature.PUBLIC_KEY_SIZE]u8,
    ) AuthenticationResult {
        if (!self.challenge_store.validateChallenge(challenge_bytes)) {
            return .expired_challenge;
        }

        const challenge = self.challenge_store.getChallenge(challenge_bytes) orelse return .unknown_error;
        if (challenge.used) return .used_challenge;

        const sig = signature.Signature.fromBytes(signature_bytes);
        const pubkey = signature.PublicKey.fromBytes(public_key) catch return .invalid_identity;

        const challenge_hash = hash.hashData(&challenge_bytes);
        if (!signature.verify(&challenge_hash, sig, pubkey)) {
            return .invalid_signature;
        }

        self.challenge_store.consumeChallenge(challenge_bytes) catch return .unknown_error;
        return .success;
    }
};

pub fn generateChallenge() [CHALLENGE_SIZE]u8 {
    var challenge: [CHALLENGE_SIZE]u8 = undefined;
    std.crypto.random.bytes(&challenge);
    return challenge;
}

pub fn signChallenge(challenge: [CHALLENGE_SIZE]u8, keypair: signature.KeyPair) !signature.Signature {
    const challenge_hash = hash.hashData(&challenge);
    return signature.sign(&challenge_hash, keypair);
}

pub fn verifyChallengeResponse(
    challenge: [CHALLENGE_SIZE]u8,
    signature_bytes: [signature.SIGNATURE_SIZE]u8,
    public_key: [signature.PUBLIC_KEY_SIZE]u8,
) bool {
    const sig = signature.Signature.fromBytes(signature_bytes);
    const pubkey = signature.PublicKey.fromBytes(public_key) catch return false;
    const challenge_hash = hash.hashData(&challenge);
    return signature.verify(&challenge_hash, sig, pubkey);
}

test "ChallengeStore initialization" {
    const allocator = std.testing.allocator;
    var store = ChallengeStore.init(allocator);
    defer store.deinit();
    try std.testing.expect(store.challenges.count() == 0);
}

test "ChallengeStore create/get challenge" {
    const allocator = std.testing.allocator;
    var store = ChallengeStore.init(allocator);
    defer store.deinit();

    const challenge = try store.createChallenge("test-identity");
    try std.testing.expect(store.challenges.count() == 1);

    const retrieved = store.getChallenge(challenge.challenge);
    try std.testing.expect(retrieved != null);
    try std.testing.expect(retrieved.?.used == false);
}

test "ChallengeStore validate/expire challenge" {
    const allocator = std.testing.allocator;
    var store = ChallengeStore.init(allocator);
    defer store.deinit();

    const challenge = try store.createChallenge("test-identity");
    try std.testing.expect(store.validateChallenge(challenge.challenge) == true);

    store.consumeChallenge(challenge.challenge);
    try std.testing.expect(store.validateChallenge(challenge.challenge) == false);
}

test "generateChallenge" {
    const c1 = generateChallenge();
    const c2 = generateChallenge();
    try std.testing.expect(!std.mem.eql(u8, &c1, &c2));
}

test "signChallenge/verifyChallengeResponse" {
    const keypair = signature.generateKeyPair();
    const challenge = generateChallenge();

    const sig = try signChallenge(challenge, keypair);
    const valid = verifyChallengeResponse(challenge, sig.toBytes(), keypair.public_key.bytes);
    try std.testing.expect(valid == true);
}

test "verifyChallengeResponse rejects wrong signature" {
    const keypair1 = signature.generateKeyPair();
    const keypair2 = signature.generateKeyPair();
    const challenge = generateChallenge();

    const sig = try signChallenge(challenge, keypair1);
    const valid = verifyChallengeResponse(challenge, sig.toBytes(), keypair2.public_key.bytes);
    try std.testing.expect(valid == false);
}
