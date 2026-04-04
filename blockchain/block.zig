const std = @import("std");
const h = @import("hash.zig");

pub const HASH_SIZE = h.digest_length;
pub const Hash = [HASH_SIZE]u8;

pub const Block = struct {
    const Self = @This();

    index: u32,
    timestamp: u64,
    previous_hash: Hash,
    transactions: []const []const u8,
    hash: Hash,
    nonce: u64,

    pub fn hashBlock(self: *const Self) Hash {
        var buf: [256]u8 = undefined;
        var offset: usize = 0;

        @memcpy(buf[offset..][0..4], std.mem.asBytes(&self.index));
        offset += 4;
        @memcpy(buf[offset..][0..8], std.mem.asBytes(&self.timestamp));
        offset += 8;
        @memcpy(buf[offset..][0..HASH_SIZE], &self.previous_hash);
        offset += HASH_SIZE;

        for (self.transactions) |tx| {
            @memcpy(buf[offset..][0..tx.len], tx);
            offset += tx.len;
        }
        @memcpy(buf[offset..][0..8], std.mem.asBytes(&self.nonce));

        return h.hash(buf[0..offset]);
    }

    pub fn mine(self: *Self, difficulty: u8) void {
        var nonce: u64 = 0;
        while (true) {
            self.nonce = nonce;
            self.hash = self.hashBlock();
            if (self.validHash(difficulty)) break;
            nonce += 1;
        }
    }

    pub fn validHash(self: *const Self, difficulty: u8) bool {
        return switch (difficulty) {
            1 => self.hash[0] == 0,
            2 => self.hash[0] == 0 and self.hash[1] == 0,
            3 => self.hash[0] == 0 and self.hash[1] == 0 and self.hash[2] == 0,
            4 => self.hash[0] == 0 and self.hash[1] == 0 and self.hash[2] == 0 and self.hash[3] == 0,
            else => self.hash[0] == 0,
        };
    }

    pub fn valid(self: *const Self, previous_hash: Hash, difficulty: u8) bool {
        if (!std.mem.eql(u8, &self.previous_hash, &previous_hash)) return false;
        const computed = self.hashBlock();
        if (!std.mem.eql(u8, &self.hash, &computed)) return false;
        return self.validHash(difficulty);
    }
};

pub fn genesisBlock() Block {
    const genesis_hash = h.hash("Genesis Block");
    return Block{
        .index = 0,
        .timestamp = 0,
        .previous_hash = genesis_hash,
        .transactions = &.{},
        .hash = genesis_hash,
        .nonce = 0,
    };
}

test "genesisBlock" {
    const block = genesisBlock();
    try std.testing.expect(block.index == 0);
    try std.testing.expect(block.timestamp == 0);
}

test "hashBlock deterministic" {
    var block = Block{
        .index = 1,
        .timestamp = 1234567890,
        .previous_hash = [_]u8{0} ** HASH_SIZE,
        .transactions = &.{"test"},
        .hash = undefined,
        .nonce = 0,
    };
    const h1 = block.hashBlock();
    const h2 = block.hashBlock();
    try std.testing.expect(std.mem.eql(u8, &h1, &h2));
}

test "different blocks different hashes" {
    var block1 = Block{
        .index = 1,
        .timestamp = 1234567890,
        .previous_hash = [_]u8{0} ** HASH_SIZE,
        .transactions = &.{"tx1"},
        .hash = undefined,
        .nonce = 0,
    };
    var block2 = Block{
        .index = 1,
        .timestamp = 1234567890,
        .previous_hash = [_]u8{0} ** HASH_SIZE,
        .transactions = &.{"tx2"},
        .hash = undefined,
        .nonce = 0,
    };
    const h1 = block1.hashBlock();
    const h2 = block2.hashBlock();
    try std.testing.expect(!std.mem.eql(u8, &h1, &h2));
}

test "valid detects tampering" {
    var block = Block{
        .index = 1,
        .timestamp = 1234567890,
        .previous_hash = [_]u8{0} ** HASH_SIZE,
        .transactions = &.{"test"},
        .hash = undefined,
        .nonce = 42,
    };
    block.hash = block.hashBlock();
    const prev_hash = [_]u8{1} ** HASH_SIZE;
    try std.testing.expect(!block.valid(prev_hash, 1));
}
