const std = @import("std");
const peer = @import("peer.zig");

pub const PeerId = peer.PeerId;

pub const Address = struct {
    ip: []const u8,
    port: u16,
    peer_id: PeerId,

    pub fn toString(self: Address, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}:{d}/{x}", .{
            self.ip,
            self.port,
            std.fmt.bytesToHex(self.peer_id, .lower),
        });
    }
};
