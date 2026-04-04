const std = @import("std");
const cid_mod = @import("cid.zig");

pub const Type = enum(u8) {
    file = 1,
    directory = 2,
    symlink = 3,
    block = 4,
    directory_sharded = 5,
};

pub const Data = struct {
    typ: Type,
    data: []const u8,
    filesize: u64 = 0,
    blocksizes: []const u64 = &.{},

    pub fn file(data: []const u8) Data {
        return .{
            .typ = .file,
            .data = data,
            .filesize = data.len,
        };
    }

    pub fn directory() Data {
        return .{
            .typ = .directory,
            .data = &.{},
            .filesize = 0,
        };
    }
};

pub const Node = struct {
    links: []Link,
    data: Data,

    pub const Link = struct {
        name: []const u8,
        cid: cid_mod.CID,
        size: u64,
    };
};

pub const Directory = struct {
    entries: std.StringHashMap(Entry),
    allocator: std.mem.Allocator,

    pub const Entry = struct {
        cid: cid_mod.CID,
        size: u64,
        node_type: Type,
    };

    pub fn init(allocator: std.mem.Allocator) Directory {
        return .{
            .entries = std.StringHashMap(Entry).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Directory) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.entries.deinit();
    }

    pub fn put(self: *Directory, name: []const u8, entry: Entry) !void {
        const key = try self.allocator.dupe(u8, name);
        try self.entries.put(key, entry);
    }

    pub fn get(self: *Directory, name: []const u8) ?Entry {
        return self.entries.get(name);
    }
};

pub fn createFileNode(_: std.mem.Allocator, data: []const u8, _: []const u8) !Node {
    const data_node = Data.file(data);
    return Node{
        .links = &.{},
        .data = data_node,
    };
}

pub fn createDirectoryNode(_: std.mem.Allocator, entries: []const Node.Link) !Node {
    return Node{
        .links = entries,
        .data = Data.directory(),
    };
}
