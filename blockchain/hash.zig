const std = @import("std");

pub const digest_length: comptime_int = 32;

pub fn hash(data: []const u8) [digest_length]u8 {
    var result: [digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &result, .{});
    return result;
}

test "hash" {
    const result = hash("hello world");
    try std.testing.expect(result.len == digest_length);
}

test "deterministic" {
    const a = hash("test");
    const b = hash("test");
    try std.testing.expect(std.mem.eql(u8, &a, &b));
}

test "different inputs" {
    const a = hash("input1");
    const b = hash("input2");
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
}

test "known vector" {
    const result = hash("hello world");
    try std.testing.expectEqualStrings(
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
        &std.fmt.bytesToHex(result, .lower),
    );
}

test "empty input" {
    const result = hash("");
    try std.testing.expect(result.len == digest_length);
}
