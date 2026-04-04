const std = @import("std");
const crypto = @import("crypto.zig");
const hash = @import("hash.zig");

pub const HASH_SIZE = crypto.HASH_SIZE;
pub const Hash = [HASH_SIZE]u8;

pub const Block = struct {
    index: u32,
    timestamp: u64,
    previous_hash: Hash,
    transactions: []const []const u8,
    hash: Hash,
    nonce: u64,

    pub fn calculateHash(self: *const Block) Hash {
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

        return hash.hashData(buf[0..offset]);
    }

    pub fn mine(self: *Block, difficulty: u8) void {
        var nonce: u64 = 0;
        while (true) {
            self.nonce = nonce;
            self.hash = self.calculateHash();
            const valid = switch (difficulty) {
                1 => self.hash[0] == 0,
                2 => self.hash[0] == 0 and self.hash[1] == 0,
                3 => self.hash[0] == 0 and self.hash[1] == 0 and self.hash[2] == 0,
                4 => self.hash[0] == 0 and self.hash[1] == 0 and self.hash[2] == 0 and self.hash[3] == 0,
                else => self.hash[0] == 0,
            };
            if (valid) break;
            nonce += 1;
        }
    }

    pub fn isValid(self: *const Block, previous_hash: Hash, difficulty: u8) bool {
        if (!std.mem.eql(u8, &self.previous_hash, &previous_hash)) return false;
        const computed = self.calculateHash();
        if (!std.mem.eql(u8, &self.hash, &computed)) return false;
        const valid = switch (difficulty) {
            1 => self.hash[0] == 0,
            2 => self.hash[0] == 0 and self.hash[1] == 0,
            3 => self.hash[0] == 0 and self.hash[1] == 0 and self.hash[2] == 0,
            4 => self.hash[0] == 0 and self.hash[1] == 0 and self.hash[2] == 0 and self.hash[3] == 0,
            else => self.hash[0] == 0,
        };
        return valid;
    }
};

pub fn createGenesisBlock() Block {
    const genesis_hash = hash.hashData("Genesis Block");
    return Block{
        .index = 0,
        .timestamp = 0,
        .previous_hash = genesis_hash,
        .transactions = &.{},
        .hash = genesis_hash,
        .nonce = 0,
    };
}

test "createGenesisBlock" {
    const block = createGenesisBlock();
    try std.testing.expect(block.index == 0);
    try std.testing.expect(block.timestamp == 0);
}

test "calculateHash is deterministic" {
    var block = Block{
        .index = 1,
        .timestamp = 1234567890,
        .previous_hash = [_]u8{0} ** HASH_SIZE,
        .transactions = &.{"test transaction"},
        .hash = undefined,
        .nonce = 0,
    };
    const hash1 = block.calculateHash();
    const hash2 = block.calculateHash();
    try std.testing.expect(std.mem.eql(u8, &hash1, &hash2));
}

test "different blocks produce different hashes" {
    var block1 = Block{
        .index = 1,
        .timestamp = 1234567890,
        .previous_hash = [_]u8{0} ** HASH_SIZE,
        .transactions = &.{"transaction 1"},
        .hash = undefined,
        .nonce = 0,
    };
    var block2 = Block{
        .index = 1,
        .timestamp = 1234567890,
        .previous_hash = [_]u8{0} ** HASH_SIZE,
        .transactions = &.{"transaction 2"},
        .hash = undefined,
        .nonce = 0,
    };
    const hash1 = block1.calculateHash();
    const hash2 = block2.calculateHash();
    try std.testing.expect(!std.mem.eql(u8, &hash1, &hash2));
}

test "isValid detects tampered block" {
    var block = Block{
        .index = 1,
        .timestamp = 1234567890,
        .previous_hash = [_]u8{0} ** HASH_SIZE,
        .transactions = &.{"test"},
        .hash = undefined,
        .nonce = 42,
    };
    block.hash = block.calculateHash();
    const prev_hash = [_]u8{1} ** HASH_SIZE;
    try std.testing.expect(!block.isValid(prev_hash, 1));
}
