const std = @import("std");

pub const Multihash = struct {
    code: Code,
    digest: []const u8,

    pub const Code = enum(u64) {
        identity = 0x00,
        sha1 = 0x11,
        sha2_256 = 0x12,
        sha2_512 = 0x13,
        blake3 = 0x1e,
        keccak_256 = 0x1b,

        pub fn fromCode(code: u64) ?Code {
            inline for (std.meta.fields(Code)) |field| {
                if (@intFromEnum(@field(Code, field.name)) == code) {
                    return @field(Code, field.name);
                }
            }
            return null;
        }
    };

    pub fn fromBytes(bytes: []const u8) Multihash {
        if (bytes.len < 3) return undefined;
        const code = Multihash.Code.fromCode(bytes[0]) orelse return undefined;
        const len = bytes[1];
        if (bytes.len < 2 + @as(usize, len) + 2) return undefined;
        const digest = bytes[2..][0..len];
        return .{ .code = code, .digest = digest };
    }

    pub fn toBytes(self: Multihash, allocator: std.mem.Allocator) ![]u8 {
        var list = std.ArrayList(u8).init(allocator);
        errdefer list.deinit();
        try list.append(@intFromEnum(self.code));
        try list.append(@as(u8, @truncate(self.digest.len)));
        try list.appendSlice(self.digest);
        const raw = try list.toOwnedSlice();
        const raw_with_sum = try computeChecksum(raw, self.code);
        errdefer allocator.free(raw_with_sum);
        try list.appendSlice(raw_with_sum);
        return list.toOwnedSlice();
    }

    pub fn toBytesAlloc(self: Multihash, allocator: std.mem.Allocator) ![]u8 {
        var list = std.ArrayList(u8).init(allocator);
        errdefer list.deinit();
        try list.append(@intFromEnum(self.code));
        try list.append(@as(u8, @truncate(self.digest.len)));
        try list.appendSlice(self.digest);
        return try list.toOwnedSlice();
    }

    fn computeChecksum(data: []const u8, code: Code) ![]u8 {
        const hash = switch (code) {
            .sha2_256 => try sha256(data),
            else => return error.UnsupportedHash,
        };
        return hash[0..2];
    }

    fn sha256(data: []const u8) ![32]u8 {
        var ctx: [64]u8 = undefined;
        @memset(&ctx, 0);
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(data, &hash, .{});
        return hash;
    }
};

pub fn createMultihash(allocator: std.mem.Allocator, data: []const u8, code: Multihash.Code) !Multihash {
    const digest = switch (code) {
        .sha2_256 => blk: {
            var hash: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(data, &hash, .{});
            break :blk try allocator.dupe(u8, &hash);
        },
        .identity => try allocator.dupe(u8, data),
        else => return error.UnsupportedHash,
    };
    return .{ .code = code, .digest = digest };
}
