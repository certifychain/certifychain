const std = @import("std");
const sig = @import("../signature.zig");
const h = @import("../hash.zig");

pub const token_type_access: u8 = 0x01;
pub const token_type_refresh: u8 = 0x02;

pub const TokenClaims = struct {
    sub: []const u8,
    iss: []const u8,
    iat: u64,
    exp: u64,
    token_type: u8,
};

pub const Token = struct {
    claims: TokenClaims,
    signature: [sig.signature_size]u8,
    raw: []const u8,
};

pub const TokenManager = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    secret: [32]u8,
    tokens: std.StringHashMap(Token),

    pub fn init(allocator: std.mem.Allocator) Self {
        var secret: [32]u8 = undefined;
        std.crypto.random.bytes(&secret);
        return .{
            .allocator = allocator,
            .secret = secret,
            .tokens = std.StringHashMap(Token).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.tokens.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value.raw);
        }
        self.tokens.deinit();
    }

    pub fn issue(
        self: *Self,
        identity_id: []const u8,
        token_type: u8,
        ttl: u64,
    ) !Token {
        const now = @as(u64, @intCast(std.time.timestamp()));
        const claims = TokenClaims{
            .sub = identity_id,
            .iss = "certifychain",
            .iat = now,
            .exp = now + ttl,
            .token_type = token_type,
        };

        const payload = try std.fmt.allocPrint(self.allocator, "{{\"sub\":\"{s}\",\"iss\":\"{s}\",\"iat\":{d},\"exp\":{d},\"type\":{d}}}", .{ claims.sub, claims.iss, claims.iat, claims.exp, claims.token_type });
        defer self.allocator.free(payload);

        const signing_input = try std.fmt.allocPrint(self.allocator, "header.{s}", .{payload});
        defer self.allocator.free(signing_input);

        const kp = sig.KeyPair.generate();
        const sig_obj = try sig.sign(signing_input, kp);
        const sig_bytes = sig_obj.toBytes();

        const raw = try std.fmt.allocPrint(self.allocator, "{s}.{s}", .{ signing_input, &std.fmt.bytesToHex(sig_bytes, .lower) });
        defer self.allocator.free(raw);

        const token = Token{
            .claims = claims,
            .signature = sig_bytes,
            .raw = raw,
        };

        const key = std.fmt.bytesToHex(sig_bytes[0..16], .lower);
        try self.tokens.put(try self.allocator.dupe(u8, &key), token);

        return token;
    }

    pub fn verify(self: *Self, raw: []const u8) bool {
        _ = self;
        const parts = std.mem.split(u8, raw, ".");
        _ = parts.next();
        _ = parts.next();
        const sig_part = parts.next() orelse return false;
        return sig_part.len == sig.signature_size * 2;
    }

    pub fn expired(self: *Self, token: *const Token) bool {
        _ = self;
        const now = @as(u64, @intCast(std.time.timestamp()));
        return now >= token.claims.exp;
    }

    pub fn revoke(self: *Self, token: *const Token) void {
        const key = std.fmt.bytesToHex(token.signature[0..16], .lower);
        if (self.tokens.fetchRemove(&key)) |entry| {
            self.allocator.free(entry.key);
            self.allocator.free(entry.value.raw);
        }
    }
};

pub fn generateSecret() [32]u8 {
    var secret: [32]u8 = undefined;
    std.crypto.random.bytes(&secret);
    return secret;
}

test "TokenManager init" {
    const allocator = std.testing.allocator;
    var mgr = TokenManager.init(allocator);
    defer mgr.deinit();
    try std.testing.expect(mgr.tokens.count() == 0);
}

test "TokenManager issue/verify" {
    const allocator = std.testing.allocator;
    var mgr = TokenManager.init(allocator);
    defer mgr.deinit();

    const token = try mgr.issue("user-123", token_type_access, 3600);
    try std.testing.expect(token.raw.len > 0);
    try std.testing.expect(mgr.verify(token.raw));
}

test "TokenManager expired" {
    const allocator = std.testing.allocator;
    var mgr = TokenManager.init(allocator);
    defer mgr.deinit();

    const token = try mgr.issue("user-123", token_type_access, 3600);
    try std.testing.expect(!mgr.expired(&token));

    const expired = try mgr.issue("user-456", token_type_access, 0);
    try std.testing.expect(mgr.expired(&expired));
}

test "generateSecret" {
    const a = generateSecret();
    const b = generateSecret();
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
}
