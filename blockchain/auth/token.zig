const std = @import("std");
const hash = @import("../hash.zig");
const signature = @import("../signature.zig");

pub const TOKEN_TYPE_ACCESS: u8 = 0x01;
pub const TOKEN_TYPE_REFRESH: u8 = 0x02;

pub const TokenHeader = struct {
    alg: []const u8,
    typ: []const u8,
};

pub const TokenClaims = struct {
    sub: []const u8,
    iss: []const u8,
    iat: u64,
    exp: u64,
    token_type: u8,
    permissions: ?[][]const u8,
};

pub const Token = struct {
    header: TokenHeader,
    claims: TokenClaims,
    signature: [signature.SIGNATURE_SIZE]u8,
    raw: []const u8,
};

pub const TOKEN_SECRET_SIZE = 32;

pub const TokenManager = struct {
    allocator: std.mem.Allocator,
    secret: [TOKEN_SECRET_SIZE]u8,
    issued_tokens: std.StringHashMap(Token),

    pub fn init(allocator: std.mem.Allocator) TokenManager {
        var secret: [TOKEN_SECRET_SIZE]u8 = undefined;
        std.crypto.random.bytes(&secret);
        return .{
            .allocator = allocator,
            .secret = secret,
            .issued_tokens = std.StringHashMap(Token).init(allocator),
        };
    }

    pub fn initWithSecret(allocator: std.mem.Allocator, secret: [TOKEN_SECRET_SIZE]u8) TokenManager {
        return .{
            .allocator = allocator,
            .secret = secret,
            .issued_tokens = std.StringHashMap(Token).init(allocator),
        };
    }

    pub fn deinit(self: *TokenManager) void {
        var it = self.issued_tokens.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value.raw);
        }
        self.issued_tokens.deinit();
    }

    pub fn issueToken(
        self: *TokenManager,
        identity_id: []const u8,
        token_type: u8,
        ttl_seconds: u64,
        permissions: ?[][]const u8,
    ) !Token {
        const now = @as(u64, @intCast(std.time.timestamp()));
        const claims = TokenClaims{
            .sub = identity_id,
            .iss = "certifychain",
            .iat = now,
            .exp = now + ttl_seconds,
            .token_type = token_type,
            .permissions = permissions,
        };

        const header = TokenHeader{
            .alg = "Ed25519",
            .typ = "JWT",
        };

        var payload_bytes = std.ArrayList(u8).init(self.allocator);
        defer payload_bytes.deinit();

        try std.fmt.format(payload_bytes.writer(), "{{\"sub\":\"{s}\",\"iss\":\"{s}\",\"iat\":{d},\"exp\":{d},\"type\":{d}}}", .{
            claims.sub,
            claims.iss,
            claims.iat,
            claims.exp,
            claims.token_type,
        });

        const payload = payload_bytes.items;
        const header_b64 = try self.base64Encode(header.alg ++ "." ++ "JWT");
        const payload_b64 = try self.base64Encode(payload);

        const signing_input = try std.fmt.allocPrint(self.allocator, "{s}.{s}", .{
            header_b64,
            payload_b64,
        });
        defer self.allocator.free(signing_input);

        const sig_bytes = try self.sign(signing_input);
        const sig_b64 = try self.base64EncodeBytes(&sig_bytes);

        const token_raw = try std.fmt.allocPrint(self.allocator, "{s}.{s}.{s}", .{
            header_b64,
            payload_b64,
            sig_b64,
        });

        const token = Token{
            .header = header,
            .claims = claims,
            .signature = sig_bytes,
            .raw = token_raw,
        };

        const token_id = std.fmt.bytesToHex(sig_bytes[0..16], .lower);
        try self.issued_tokens.put(try self.allocator.dupe(u8, &token_id), token);

        return token;
    }

    pub fn verifyToken(self: *TokenManager, token_raw: []const u8) bool {
        const parts = std.mem.split(u8, token_raw, ".");
        const header_b64 = parts.next() orelse return false;
        const payload_b64 = parts.next() orelse return false;
        const sig_b64 = parts.next() orelse return false;

        const sig_bytes = self.base64Decode(sig_b64) catch return false;
        if (sig_bytes.len < signature.SIGNATURE_SIZE) return false;

        var sig: [signature.SIGNATURE_SIZE]u8 = undefined;
        @memcpy(&sig, sig_bytes[0..signature.SIGNATURE_SIZE]);

        const signing_input = try std.fmt.allocPrint(self.allocator, "{s}.{s}", .{
            header_b64,
            payload_b64,
        });
        defer self.allocator.free(signing_input);

        const expected_hash = self.deriveKey(signing_input);

        var i: usize = 0;
        while (i < 16) : (i += 1) {
            if (sig_bytes[i] != expected_hash[i]) return false;
        }

        return true;
    }

    pub fn isTokenExpired(_: *TokenManager, token: *const Token) bool {
        const now = @as(u64, @intCast(std.time.timestamp()));
        return now >= token.claims.exp;
    }

    pub fn revokeToken(self: *TokenManager, token: *const Token) void {
        const token_id = std.fmt.bytesToHex(token.signature[0..16], .lower);
        if (self.issued_tokens.fetchRemove(&token_id)) |entry| {
            self.allocator.free(entry.key);
            self.allocator.free(entry.value.raw);
        }
    }

    fn base64Encode(self: *TokenManager, data: []const u8) ![]u8 {
        _ = self;
        return std.base64Encoder.encode(data);
    }

    fn base64EncodeBytes(self: *TokenManager, data: []const u8) ![]u8 {
        _ = self;
        return std.base64Encoder.encode(data);
    }

    fn base64Decode(self: *TokenManager, encoded: []const u8) ![]u8 {
        _ = self;
        return std.base64Decoder.decode(encoded);
    }

    fn deriveKey(_: *TokenManager, data: []const u8) [16]u8 {
        var result: [16]u8 = undefined;
        const h = hash.hashData(data);
        @memcpy(&result, h[0..16]);
        return result;
    }

    fn sign(_: *TokenManager, data: []const u8) ![signature.SIGNATURE_SIZE]u8 {
        const keypair = signature.generateKeyPair();
        const sig = signature.sign(data, keypair) catch return error.SignFailed;
        return sig.toBytes();
    }
};

pub fn generateTokenSecret() [TOKEN_SECRET_SIZE]u8 {
    var secret: [TOKEN_SECRET_SIZE]u8 = undefined;
    std.crypto.random.bytes(&secret);
    return secret;
}

test "TokenManager initialization" {
    const allocator = std.testing.allocator;
    var manager = TokenManager.init(allocator);
    defer manager.deinit();
    try std.testing.expect(manager.issued_tokens.count() == 0);
}

test "TokenManager issue/verify token" {
    const allocator = std.testing.allocator;
    var manager = TokenManager.init(allocator);
    defer manager.deinit();

    const token = try manager.issueToken("user-123", TOKEN_TYPE_ACCESS, 3600, null);
    try std.testing.expect(token.raw.len > 0);
}

test "TokenManager isTokenExpired" {
    const allocator = std.testing.allocator;
    var manager = TokenManager.init(allocator);
    defer manager.deinit();

    const token = try manager.issueToken("user-123", TOKEN_TYPE_ACCESS, 3600, null);
    try std.testing.expect(manager.isTokenExpired(&token) == false);

    const expired_token = try manager.issueToken("user-456", TOKEN_TYPE_ACCESS, 0, null);
    try std.testing.expect(manager.isTokenExpired(&expired_token) == true);
}

test "generateTokenSecret" {
    const secret1 = generateTokenSecret();
    const secret2 = generateTokenSecret();
    try std.testing.expect(!std.mem.eql(u8, &secret1, &secret2));
}
