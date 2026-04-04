const std = @import("std");

pub const MessageType = enum(u8) {
    handshake = 0x01,
    ping = 0x02,
    pong = 0x03,
    transaction = 0x10,
    transaction_inv = 0x11,
    transaction_get = 0x12,
    block = 0x20,
    block_inv = 0x21,
    block_get = 0x22,
    get_peers = 0x30,
    peers = 0x31,
    certificate_query = 0x40,
    certificate_response = 0x41,
    certificate_validation = 0x42,
    certificate_validation_response = 0x43,
};

pub const Message = struct {
    const Self = @This();

    msg_type: MessageType,
    payload: []u8,
    timestamp: u64,
    ttl: u8,

    pub fn create(msg_type: MessageType, payload: []u8) Self {
        return .{
            .msg_type = msg_type,
            .payload = payload,
            .timestamp = @as(u64, @intCast(std.time.timestamp())),
            .ttl = 3,
        };
    }
};
