const std = @import("std");
const ipfs = @import("ipfs");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    std.debug.print("=== IPFS Module Demo ===\n\n", .{});

    std.debug.print("1. Creating CID from data...\n", .{});
    const data = "Hello, IPFS!";
    const mh = try ipfs.multihash.createMultihash(allocator, data, .sha2_256);
    defer allocator.free(mh.digest);
    const cid = ipfs.CID.v1(.dag_pb, mh);
    std.debug.print("   CID created: version={}, codec={s}\n", .{
        cid.version,
        cid.codec.toString(),
    });

    std.debug.print("\n2. Gateway client...\n", .{});
    var gateway = ipfs.GatewayClient.init(allocator, "https://cloudflare-ipfs.com");
    defer gateway.deinit();
    _ = &gateway;
    std.debug.print("   Gateway URL: {s}\n", .{gateway.base_url});

    std.debug.print("\n3. Trustless gateway (CAR/block fetching)...\n", .{});
    std.debug.print("   Use: trustless.getCAR() or trustless.getBlock()\n", .{});

    std.debug.print("\n4. Routing (Kademlia DHT)...\n", .{});
    _ = ipfs.routing.Routing.init(allocator);
    std.debug.print("   Routing initialized\n", .{});

    std.debug.print("\n5. UnixFS...\n", .{});
    const file_data = ipfs.unixfs.Data.file(data);
    std.debug.print("   UnixFS file node: type={}, size={}\n", .{
        file_data.typ,
        file_data.filesize,
    });

    std.debug.print("\n=== Demo Complete ===\n", .{});
}

test "CID creation" {
    const allocator = std.testing.allocator;
    const data = "test";
    const mh = try ipfs.multihash.createMultihash(allocator, data, .sha2_256);
    defer allocator.free(mh.digest);
    const cid = ipfs.CID.v1(.dag_pb, mh);
    try std.testing.expect(cid.version == 1);
    try std.testing.expect(cid.codec == .dag_pb);
}
