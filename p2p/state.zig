const std = @import("std");
const peer = @import("peer.zig");
const address = @import("address.zig");

pub const PeerId = peer.PeerId;

pub const ConnectionState = enum {
    disconnected,
    connecting,
    connected,
    handshake,
    active,
};

pub const Peer = struct {
    id: PeerId,
    address: address.Address,
    state: ConnectionState,
    last_seen: u64,
    trusted: bool,

    pub fn isActive(self: *const Peer) bool {
        return self.state == .active;
    }
};
