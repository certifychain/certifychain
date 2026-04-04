const std = @import("std");
const multihash = @import("multihash.zig");

pub const CIDv1 = struct {
    version: u8 = 1,
    codec: Codec,
    multihash: multihash.Multihash,
};

pub const Codec = enum(u64) {
    dag_pb = 0x70,
    raw = 0x55,
    dag_cbor = 0x71,
    dag_json = 0x85,
    identity = 0x00,

    pub fn fromString(str: []const u8) ?Codec {
        if (std.mem.eql(u8, str, "dag-pb")) return .dag_pb;
        if (std.mem.eql(u8, str, "raw")) return .raw;
        if (std.mem.eql(u8, str, "dag-cbor")) return .dag_cbor;
        if (std.mem.eql(u8, str, "dag-json")) return .dag_json;
        if (std.mem.eql(u8, str, "identity")) return .identity;
        return null;
    }

    pub fn toString(self: Codec) []const u8 {
        return switch (self) {
            .dag_pb => "dag-pb",
            .raw => "raw",
            .dag_cbor => "dag-cbor",
            .dag_json => "dag-json",
            .identity => "identity",
        };
    }
};

pub const CID = struct {
    const Self = @This();

    version: u8,
    codec: Codec,
    multihash: multihash.Multihash,

    pub fn v0(cid_str: []const u8) !Self {
        if (cid_str.len != 46 or cid_str[0] != 'Q' or cid_str[1] != 'm') {
            return error.InvalidCidV0;
        }
        const decoded = try std.base64.decodeStd64(cid_str[2..]);
        const mh = multihash.Multihash.fromBytes(decoded);
        return .{
            .version = 0,
            .codec = .dag_pb,
            .multihash = mh,
        };
    }

    pub fn v1(codec: Codec, mh: multihash.Multihash) Self {
        return .{
            .version = 1,
            .codec = codec,
            .multihash = mh,
        };
    }

    pub fn parse(cid_str: []const u8) !Self {
        if (cid_str.len >= 2 and std.mem.startsWith(u8, cid_str, "Qm")) {
            return Self.v0(cid_str);
        }
        if (!std.mem.startsWith(u8, cid_str, "bafy")) {
            return error.InvalidCid;
        }
        const decoded = try std.base64.url_decode(cid_str[4..]);
        if (decoded.len < 4) return error.InvalidCid;
        const version = decoded[0];
        if (version != 1) return error.UnsupportedCidVersion;
        const codec = @as(Codec, @enumFromInt(@as(u64, decoded[1]) << 8 | decoded[2]));
        const mh_bytes = decoded[3..];
        const mh = multihash.Multihash.fromBytes(mh_bytes);
        return .{
            .version = version,
            .codec = codec,
            .multihash = mh,
        };
    }

    pub fn toString(self: Self, allocator: std.mem.Allocator) ![]u8 {
        var list = std.ArrayList(u8).init(allocator);
        errdefer list.deinit();
        try list.appendSlice(switch (self.version) {
            0 => "Qm",
            1 => "bafy",
            else => return error.UnsupportedCidVersion,
        });
        const mh_bytes = self.multihash.toBytes();
        switch (self.version) {
            0 => {
                try list.appendSlice(std.base64.Encoder.options(.{
                    .padding = null,
                }).encode(mh_bytes));
            },
            1 => {
                var header: [3]u8 = undefined;
                header[0] = 1;
                header[1] = @intFromEnum(self.codec) >> 8;
                header[2] = @intFromEnum(self.codec) & 0xFF;
                try list.appendSlice(std.base64.Encoder.options(.{
                    .padding = null,
                }).encode(header[0..]));
                try list.appendSlice(std.base64.Encoder.options(.{
                    .padding = null,
                }).encode(mh_bytes));
            },
            else => return error.UnsupportedCidVersion,
        }
        return list.toOwnedSlice();
    }

    pub fn hash(self: Self) []const u8 {
        return self.multihash.digest;
    }
};
