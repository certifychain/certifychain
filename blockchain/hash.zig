const std = @import("std");

pub const HASH_SIZE = 32;

pub fn hashData(data: []const u8) [HASH_SIZE]u8 {
    var hash: [HASH_SIZE]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &hash, .{});
    return hash;
}

pub fn hashBytes(data: []const u8) [HASH_SIZE]u8 {
    return hashData(data);
}

test "hashData produces fixed size output" {
    const data = "hello world";
    const hash = hashData(data);
    try std.testing.expect(hash.len == HASH_SIZE);
}

test "hashData is deterministic" {
    const data = "test data";
    const hash1 = hashData(data);
    const hash2 = hashData(data);
    try std.testing.expect(std.mem.eql(u8, &hash1, &hash2));
}

test "hashData different inputs produce different hashes" {
    const hash1 = hashData("input1");
    const hash2 = hashData("input2");
    try std.testing.expect(!std.mem.eql(u8, &hash1, &hash2));
}

test "hashData empty input" {
    const hash = hashData("");
    try std.testing.expect(hash.len == HASH_SIZE);
}

test "hashData known test vector" {
    const hash = hashData("hello world");
    const expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
    const hex = std.fmt.bytesToHex(hash, .lower);
    try std.testing.expectEqualStrings(expected, &hex);
}
