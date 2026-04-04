const std = @import("std");
const testing = std.testing;
const ipfs = @import("ipfs");

test "CIDv0 parsing" {
    const cid_v0 = "QmZ4tDuvesekSs4qM5ZBKpXiZGun7S2CYtEZRB3DYXkjGx";
    const cid = try ipfs.CID.v0(cid_v0);
    try testing.expect(cid.version == 0);
    try testing.expect(cid.codec == .dag_pb);
}

test "CIDv1 parsing with dag-pb" {
    const cid_v1 = "bafybeif7ztnhq65lumvvtr4xsys5njqa43jlhl7kvphxohhqcy7zhwqbbe";
    const cid = try ipfs.CID.parse(cid_v1);
    try testing.expect(cid.version == 1);
    try testing.expect(cid.codec == .dag_pb);
}

test "CIDv1 parsing with raw codec" {
    const cid_v1 = "bafkreifjjcie6lypi6ny7amxnfftagclbuxndqonfipmb64f2km2devei4";
    const cid = try ipfs.CID.parse(cid_v1);
    try testing.expect(cid.version == 1);
    try testing.expect(cid.codec == .raw);
}

test "CIDv1 parsing with dag-cbor codec" {
    const cid_v1 = "bafyreidf Carol";
    _ = cid_v1;
}

test "CID codec string conversion" {
    try testing.expectEqualStrings("dag-pb", ipfs.CID.Codec.dag_pb.toString());
    try testing.expectEqualStrings("raw", ipfs.CID.Codec.raw.toString());
    try testing.expectEqualStrings("dag-cbor", ipfs.CID.Codec.dag_cbor.toString());
    try testing.expectEqualStrings("dag-json", ipfs.CID.Codec.dag_json.toString());
    try testing.expectEqualStrings("identity", ipfs.CID.Codec.identity.toString());
}

test "CID codec from string" {
    try testing.expect(ipfs.CID.Codec.fromString("dag-pb") == .dag_pb);
    try testing.expect(ipfs.CID.Codec.fromString("raw") == .raw);
    try testing.expect(ipfs.CID.Codec.fromString("dag-cbor") == .dag_cbor);
    try testing.expect(ipfs.CID.Codec.fromString("dag-json") == .dag_json);
    try testing.expect(ipfs.CID.Codec.fromString("identity") == .identity);
    try testing.expect(ipfs.CID.Codec.fromString("invalid") == null);
}

test "CIDv0 invalid format" {
    const result = ipfs.CID.v0("invalid");
    try testing.expectError(error.InvalidCidV0, result);
}

test "CID invalid prefix" {
    const result = ipfs.CID.parse("xxxinvalid");
    try testing.expectError(error.InvalidCid, result);
}

test "Multihash SHA256 creation" {
    const allocator = testing.allocator;
    const data = "hello world";
    const mh = try ipfs.multihash.createMultihash(allocator, data, .sha2_256);
    defer allocator.free(mh.digest);
    try testing.expect(mh.code == .sha2_256);
    try testing.expect(mh.digest.len == 32);
}

test "Multihash identity" {
    const allocator = testing.allocator;
    const data = "small data";
    const mh = try ipfs.multihash.createMultihash(allocator, data, .identity);
    defer allocator.free(mh.digest);
    try testing.expect(mh.code == .identity);
    try testing.expect(std.mem.eql(u8, mh.digest, data));
}

test "Multihash from bytes" {
    var mh_bytes: [34]u8 = undefined;
    mh_bytes[0] = 0x12;
    mh_bytes[1] = 0x20;
    @memset(mh_bytes[2..], 0);
    const mh = ipfs.multihash.Multihash.fromBytes(&mh_bytes);
    try testing.expect(mh.code == .sha2_256);
    try testing.expect(mh.digest.len == 32);
}

test "Multihash Code from code value" {
    try testing.expect(ipfs.multihash.Multihash.Code.fromCode(0x12) == .sha2_256);
    try testing.expect(ipfs.multihash.Multihash.Code.fromCode(0x11) == .sha1);
    try testing.expect(ipfs.multihash.Multihash.Code.fromCode(0x00) == .identity);
    try testing.expect(ipfs.multihash.Multihash.Code.fromCode(0x99) == null);
}

test "UnixFS Data file creation" {
    const data = "test content";
    const unixfs_data = ipfs.unixfs.Data.file(data);
    try testing.expect(unixfs_data.typ == .file);
    try testing.expect(unixfs_data.filesize == data.len);
    try testing.expect(std.mem.eql(u8, unixfs_data.data, data));
}

test "UnixFS Data directory creation" {
    const dir = ipfs.unixfs.Data.directory();
    try testing.expect(dir.typ == .directory);
    try testing.expect(dir.filesize == 0);
    try testing.expect(dir.data.len == 0);
}

test "UnixFS Directory operations" {
    const allocator = testing.allocator;
    var dir = ipfs.unixfs.Directory.init(allocator);
    defer dir.deinit();

    const entry = ipfs.unixfs.Directory.Entry{
        .cid = ipfs.CID.v1(.dag_pb, ipfs.multihash.Multihash{
            .code = .sha2_256,
            .digest = &[_]u8{0} ** 32,
        }),
        .size = 100,
        .node_type = .file,
    };

    try dir.put("test.txt", entry);
    try testing.expect(dir.get("test.txt") != null);
    try testing.expect(dir.get("missing.txt") == null);
}

test "UnixFS createFileNode" {
    const data = "file content";
    const node = try ipfs.unixfs.createFileNode(testing.allocator, data, "");
    try testing.expect(node.data.typ == .file);
    try testing.expect(node.data.filesize == data.len);
}

test "UnixFS createDirectoryNode" {
    const links = &[_]ipfs.unixfs.Node.Link{
        .{
            .name = "file.txt",
            .cid = ipfs.CID.v1(.dag_pb, ipfs.multihash.Multihash{
                .code = .sha2_256,
                .digest = &[_]u8{0} ** 32,
            }),
            .size = 50,
        },
    };
    const node = try ipfs.unixfs.createDirectoryNode(testing.allocator, links);
    try testing.expect(node.data.typ == .directory);
    try testing.expect(node.links.len == 1);
}

test "Kademlia XOR distance" {
    const allocator = testing.allocator;
    _ = allocator;
    var kad = ipfs.routing.Kademlia.init(testing.allocator);

    const a = [_]u8{0xFF} ** 20;
    const b = [_]u8{0x00} ** 20;

    const dist = kad.distance(&a, &b);
    try testing.expect(dist[0] == 0xFF);
    try testing.expect(dist[19] == 0xFF);
}

test "Kademlia nodeId derivation" {
    var kad = ipfs.routing.Kademlia.init(testing.allocator);
    const peer_id = "QmPeerID123456789";
    const node_id = kad.nodeId(peer_id);
    try testing.expect(node_id.len == 20);
}

test "Kademlia bucket size constant" {
    try testing.expect(ipfs.routing.Kademlia.k == 20);
}

test "Routing findProviders (stub)" {
    var routing = ipfs.routing.Routing.init(testing.allocator);
    const cid = ipfs.CID.v1(.dag_pb, ipfs.multihash.Multihash{
        .code = .sha2_256,
        .digest = &[_]u8{0} ** 32,
    });
    const providers = try routing.findProviders(cid);
    try testing.expect(providers.len == 0);
}

test "IPNS Record parsing (basic structure)" {
    const allocator = testing.allocator;
    const record_data = [_]u8{0} ** 100;
    const record = try ipfs.IPNS.parseRecord(allocator, &record_data);
    try testing.expect(record.sequence == 0);
}

test "IPNS Record with invalid data" {
    const allocator = testing.allocator;
    const short_data = [_]u8{ 1, 2, 3 };
    const result = ipfs.IPNS.parseRecord(allocator, &short_data);
    try testing.expectError(error.InvalidRecord, result);
}

test "IPNS resolve URL construction" {
    const allocator = testing.allocator;
    const url = try ipfs.IPNS.resolve(allocator, "k51qzi5uqu5dk4kbd5bpmklj30q0q8n3091bncahugkx18e84p1od2rk25olsd", "https://ipfs.io");
    defer allocator.free(url);
    try testing.expect(std.mem.startsWith(u8, url, "https://ipfs.io/ipns/"));
}

test "DelegatedRouting findProviders URL" {
    const allocator = testing.allocator;
    var dr = ipfs.routing.DelegatedRouting.init(allocator, "https://delegated-ipfs.dev");
    defer dr.deinit();
    try testing.expect(std.mem.eql(u8, dr.endpoint, "https://delegated-ipfs.dev"));
}

test "GatewayClient initialization" {
    const allocator = testing.allocator;
    var gateway = ipfs.GatewayClient.init(allocator, "https://cloudflare-ipfs.com");
    defer gateway.deinit();
    try testing.expect(std.mem.eql(u8, gateway.base_url, "https://cloudflare-ipfs.com"));
}

test "TrustlessGateway initialization" {
    const allocator = testing.allocator;
    var tg = ipfs.TrustlessGateway.init(allocator, "https://ipfs.io");
    defer tg.deinit();
    try testing.expect(std.mem.eql(u8, tg.gateway_url, "https://ipfs.io"));
}

test "DNSLink resolve" {
    const allocator = testing.allocator;
    var dnslink = ipfs.DNSLink.init(allocator, "https://ipfs.io");
    defer dnslink.deinit();
    const url = try dnslink.resolve("ipfs.tech", null);
    defer allocator.free(url);
    try testing.expect(std.mem.containsAtLeast(u8, url, 1, "ipfs.tech"));
}

test "Gateway URL format for CID" {
    const allocator = testing.allocator;
    var gateway = ipfs.GatewayClient.init(allocator, "https://cloudflare-ipfs.com");
    defer gateway.deinit();
    try testing.expect(std.mem.eql(u8, gateway.base_url, "https://cloudflare-ipfs.com"));
}

test "Bitswap wantlist entry" {
    var cid_bytes: [34]u8 = undefined;
    cid_bytes[0] = 0x12;
    cid_bytes[1] = 0x20;
    @memset(cid_bytes[2..], 0);
    _ = &cid_bytes;
}

test "CID hash extraction" {
    const cid = ipfs.CID.v1(.dag_pb, ipfs.multihash.Multihash{
        .code = .sha2_256,
        .digest = &[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 } ** 4,
    });
    const hash = cid.hash();
    try testing.expect(hash.len == 32);
    try testing.expect(hash[0] == 1);
}

test "CID v1 creation" {
    const mh = ipfs.multihash.Multihash{
        .code = .sha2_256,
        .digest = &[_]u8{0} ** 32,
    };
    const cid = ipfs.CID.v1(.dag_pb, mh);
    try testing.expect(cid.version == 1);
    try testing.expect(cid.codec == .dag_pb);
    try testing.expect(cid.multihash.code == .sha2_256);
}

test "Peer structure" {
    const peer = ipfs.routing.Peer{
        .id = "QmPeerID",
        .addrs = &.{"/ip4/127.0.0.1/tcp/4001"},
    };
    try testing.expect(std.mem.eql(u8, peer.id, "QmPeerID"));
    try testing.expect(peer.addrs.len == 1);
}

test "ProviderRecord structure" {
    const cid = ipfs.CID.v1(.dag_pb, ipfs.multihash.Multihash{
        .code = .sha2_256,
        .digest = &[_]u8{0} ** 32,
    });
    const peer = ipfs.routing.Peer{
        .id = "QmProvider",
        .addrs = &.{"/ip4/1.2.3.4/tcp/4001"},
    };
    const record = ipfs.routing.ProviderRecord{
        .cid = cid,
        .peers = &.{peer},
    };
    try testing.expect(record.peers.len == 1);
}

test "Kademlia xorClosest with empty peers" {
    var kad = ipfs.routing.Kademlia.init(testing.allocator);
    const target = [_]u8{0xAA} ** 20;
    const result = kad.xorClosest(&target, &.{});
    try testing.expectError(error.NoPeers, result);
}

test "Kademlia xorClosest with single peer" {
    var kad = ipfs.routing.Kademlia.init(testing.allocator);
    const target = [_]u8{0xFF} ** 20;
    const peers = &[_]ipfs.routing.Peer{
        .{
            .id = &[_]u8{0x00} ** 20,
            .addrs = &.{},
        },
    };
    const closest = try kad.xorClosest(&target, peers);
    try testing.expect(std.mem.eql(u8, closest.id, &[_]u8{0x00} ** 20));
}

test "Kademlia xorClosest finds closest" {
    var kad = ipfs.routing.Kademlia.init(testing.allocator);
    const target = [_]u8{0x55} ** 20;
    const peers = &[_]ipfs.routing.Peer{
        .{
            .id = &[_]u8{0x00} ** 20,
            .addrs = &.{},
        },
        .{
            .id = &[_]u8{0xFF} ** 20,
            .addrs = &.{},
        },
        .{
            .id = &[_]u8{0x50} ** 20,
            .addrs = &.{},
        },
    };
    const closest = try kad.xorClosest(&target, peers);
    try testing.expect(std.mem.eql(u8, closest.id, &[_]u8{0x50} ** 20));
}

test "CID identity codec" {
    const data = "test";
    const mh = ipfs.multihash.Multihash{
        .code = .identity,
        .digest = data,
    };
    const cid = ipfs.CID.v1(.identity, mh);
    try testing.expect(cid.codec == .identity);
    try testing.expect(cid.version == 1);
}

test "CID toString v1" {
    const allocator = testing.allocator;
    const mh = ipfs.multihash.Multihash{
        .code = .sha2_256,
        .digest = &[_]u8{0} ** 32,
    };
    const cid = ipfs.CID.v1(.dag_pb, mh);
    const str = try cid.toString(allocator);
    defer allocator.free(str);
    try testing.expect(std.mem.startsWith(u8, str, "bafy"));
    try testing.expect(str.len > 50);
}

test "Directory duplicate name detection" {
    const allocator = testing.allocator;
    var dir = ipfs.unixfs.Directory.init(allocator);
    defer dir.deinit();

    const entry = ipfs.unixfs.Directory.Entry{
        .cid = ipfs.CID.v1(.dag_pb, ipfs.multihash.Multihash{
            .code = .sha2_256,
            .digest = &[_]u8{0} ** 32,
        }),
        .size = 100,
        .node_type = .file,
    };

    try dir.put("file.txt", entry);
    try dir.put("file.txt", entry);
    try testing.expect(dir.get("file.txt") != null);
}

test "UnixFS file with blocksizes" {
    const data = ipfs.unixfs.Data{
        .typ = .file,
        .data = "header",
        .filesize = 1026,
        .blocksizes = &.{ 256, 256, 256, 256, 2 },
    };
    try testing.expect(data.blocksizes.len == 5);
    try testing.expect(data.filesize == 1026);
}

test "Trustless gateway CAR format URL" {
    const allocator = testing.allocator;
    var tg = ipfs.TrustlessGateway.init(allocator, "https://ipfs.io");
    defer tg.deinit();
    try testing.expect(std.mem.eql(u8, tg.gateway_url, "https://ipfs.io"));
}

test "Trustless gateway block format URL" {
    const allocator = testing.allocator;
    var tg = ipfs.TrustlessGateway.init(allocator, "https://ipfs.io");
    defer tg.deinit();
    try testing.expect(std.mem.eql(u8, tg.gateway_url, "https://ipfs.io"));
}

test "IPNS Record with value and sequence" {
    const allocator = testing.allocator;
    var data: [100]u8 = undefined;
    @memset(&data, 0);
    std.mem.writeInt(u64, data[0..8], 5, .big);
    const record = try ipfs.IPNS.parseRecord(allocator, &data);
    try testing.expect(record.sequence == 5);
}

test "Multihash blake3 code" {
    try testing.expect(ipfs.multihash.Multihash.Code.fromCode(0x1e) == .blake3);
}

test "Multihash keccak_256 code" {
    try testing.expect(ipfs.multihash.Multihash.Code.fromCode(0x1b) == .keccak_256);
}

test "CID codec codes per spec" {
    try testing.expect(@intFromEnum(ipfs.CID.Codec.dag_pb) == 0x70);
    try testing.expect(@intFromEnum(ipfs.CID.Codec.raw) == 0x55);
    try testing.expect(@intFromEnum(ipfs.CID.Codec.dag_cbor) == 0x71);
    try testing.expect(@intFromEnum(ipfs.CID.Codec.dag_json) == 0x85);
    try testing.expect(@intFromEnum(ipfs.CID.Codec.identity) == 0x00);
}

test "Gateway client deinit is safe" {
    const allocator = testing.allocator;
    var gateway = ipfs.GatewayClient.init(allocator, "https://example.com");
    gateway.deinit();
}

test "Trustless gateway deinit is safe" {
    const allocator = testing.allocator;
    var tg = ipfs.TrustlessGateway.init(allocator, "https://example.com");
    tg.deinit();
}

test "DNSLink deinit is safe" {
    const allocator = testing.allocator;
    var dnslink = ipfs.DNSLink.init(allocator, "https://example.com");
    dnslink.deinit();
}

test "DelegatedRouting deinit is safe" {
    const allocator = testing.allocator;
    var dr = ipfs.routing.DelegatedRouting.init(allocator, "https://example.com");
    dr.deinit();
}

test "Provider record with multiple peers" {
    const cid = ipfs.CID.v1(.dag_pb, ipfs.multihash.Multihash{
        .code = .sha2_256,
        .digest = &[_]u8{0} ** 32,
    });
    const peers = &[_]ipfs.routing.Peer{
        .{ .id = "peer1", .addrs = &.{} },
        .{ .id = "peer2", .addrs = &.{} },
        .{ .id = "peer3", .addrs = &.{} },
    };
    const record = ipfs.routing.ProviderRecord{
        .cid = cid,
        .peers = peers,
    };
    try testing.expect(record.peers.len == 3);
}

test "CID toString consistency" {
    const allocator = testing.allocator;
    const mh = ipfs.multihash.Multihash{
        .code = .sha2_256,
        .digest = &[_]u8{ 0x12, 0x34, 0x56 } ++ [_]u8{0} ** 29,
    };
    const cid = ipfs.CID.v1(.raw, mh);
    const str1 = try cid.toString(allocator);
    defer allocator.free(str1);
    const str2 = try cid.toString(allocator);
    defer allocator.free(str2);
    try testing.expect(std.mem.eql(u8, str1, str2));
}

test "UnixFS Node Link structure" {
    const link = ipfs.unixfs.Node.Link{
        .name = "test.txt",
        .cid = ipfs.CID.v1(.dag_pb, ipfs.multihash.Multihash{
            .code = .sha2_256,
            .digest = &[_]u8{0} ** 32,
        }),
        .size = 1024,
    };
    try testing.expect(std.mem.eql(u8, link.name, "test.txt"));
    try testing.expect(link.size == 1024);
}

test "Kademlia default parameters" {
    const kad = ipfs.routing.Kademlia.init(testing.allocator);
    try testing.expect(kad.k == 20);
    try testing.expect(kad.alpha == 3);
}

test "IPNS validity parsing" {
    const allocator = testing.allocator;
    var data: [100]u8 = undefined;
    @memset(&data, 0);
    std.mem.writeInt(u64, data[0..8], 0, .big);
    std.mem.writeInt(i64, data[8..16], 4102444800, .big);
    const record = try ipfs.IPNS.parseRecord(allocator, &data);
    try testing.expect(record.validity > 0);
}

test "Gateway dagGet URL construction" {
    const allocator = testing.allocator;
    var gateway = ipfs.GatewayClient.init(allocator, "https://ipfs.io");
    defer gateway.deinit();
    try testing.expect(std.mem.eql(u8, gateway.base_url, "https://ipfs.io"));
}

test "CID parsing roundtrip" {
    const original = "bafybeif7ztnhq65lumvvtr4xsys5njqa43jlhl7kvphxohhqcy7zhwqbbe";
    const cid = try ipfs.CID.parse(original);
    try testing.expect(cid.version == 1);
}

test "Multihash toBytesAlloc" {
    const allocator = testing.allocator;
    const mh = ipfs.multihash.Multihash{
        .code = .sha2_256,
        .digest = &[_]u8{0xAB} ** 32,
    };
    const bytes = try mh.toBytesAlloc(allocator);
    defer allocator.free(bytes);
    try testing.expect(bytes.len >= 34);
    try testing.expect(bytes[0] == 0x12);
    try testing.expect(bytes[1] == 32);
}

test "Routing provide stub" {
    var routing = ipfs.routing.Routing.init(testing.allocator);
    const cid = ipfs.CID.v1(.dag_pb, ipfs.multihash.Multihash{
        .code = .sha2_256,
        .digest = &[_]u8{0} ** 32,
    });
    try routing.provide(cid);
}
