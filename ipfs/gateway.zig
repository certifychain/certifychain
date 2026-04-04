const std = @import("std");
const cid_mod = @import("cid.zig");

pub const GatewayClient = struct {
    allocator: std.mem.Allocator,
    base_url: []const u8,
    client: std.http.Client,

    pub fn init(allocator: std.mem.Allocator, base_url: []const u8) GatewayClient {
        return .{
            .allocator = allocator,
            .base_url = base_url,
            .client = std.http.Client{ .allocator = allocator },
        };
    }

    pub fn deinit(self: *GatewayClient) void {
        self.client.deinit();
    }

    pub fn fetch(self: *GatewayClient, cid_str: []const u8) ![]u8 {
        const url = try std.fmt.allocPrint(self.allocator, "{s}/ipfs/{s}", .{
            self.base_url,
            cid_str,
        });
        defer self.allocator.free(url);

        const uri = try std.Uri.parse(url);
        var req = try self.client.open(.GET, uri, .{
            .server_header_buffer = .{ .allocator = self.allocator },
        });
        defer req.deinit();

        try req.send();
        try req.wait();
        return try req.reader().readAllAlloc(self.allocator, std.math.maxInt(usize));
    }

    pub fn fetchJSON(self: *GatewayClient, cid_str: []const u8, comptime T: type) !T {
        const data = try self.fetch(cid_str);
        defer self.allocator.free(data);
        return try std.json.parseFromSlice(T, self.allocator, data, .{
            .ignore_unknown_fields = true,
        });
    }

    pub fn cat(self: *GatewayClient, cid_str: []const u8, writer: anytype) !void {
        const url = try std.fmt.allocPrint(self.allocator, "{s}/ipfs/{s}", .{
            self.base_url,
            cid_str,
        });
        defer self.allocator.free(url);

        const uri = try std.Uri.parse(url);
        var req = try self.client.open(.GET, uri, .{
            .server_header_buffer = .{ .allocator = self.allocator },
        });
        defer req.deinit();

        try req.send();
        try req.wait();
        try req.reader().writeAll(writer);
    }

    pub fn dagGet(self: *GatewayClient, cid_str: []const u8, path: ?[]const u8) ![]u8 {
        var url = try std.fmt.allocPrint(self.allocator, "{s}/ipfs/{s}", .{
            self.base_url,
            cid_str,
        });
        defer self.allocator.free(url);

        if (path) |p| {
            self.allocator.free(url);
            url = try std.fmt.allocPrint(self.allocator, "{s}/ipfs/{s}/{s}", .{
                self.base_url,
                cid_str,
                p,
            });
        }

        const uri = try std.Uri.parse(url);
        var req = try self.client.open(.GET, uri, .{
            .server_header_buffer = .{ .allocator = self.allocator },
        });
        defer req.deinit();

        req.headers.setAcceptance(.application_octet_stream);
        try req.send();
        try req.wait();
        return try req.reader().readAllAlloc(self.allocator, std.math.maxInt(usize));
    }
};

pub const TrustlessGateway = struct {
    allocator: std.mem.Allocator,
    gateway_url: []const u8,
    client: std.http.Client,

    pub fn init(allocator: std.mem.Allocator, gateway_url: []const u8) TrustlessGateway {
        return .{
            .allocator = allocator,
            .gateway_url = gateway_url,
            .client = std.http.Client{ .allocator = allocator },
        };
    }

    pub fn deinit(self: *TrustlessGateway) void {
        self.client.deinit();
    }

    pub fn getCAR(self: *TrustlessGateway, cid_str: []const u8) ![]u8 {
        const url = try std.fmt.allocPrint(self.allocator, "{s}/ipfs/{s}?format=car", .{
            self.gateway_url,
            cid_str,
        });
        defer self.allocator.free(url);

        const uri = try std.Uri.parse(url);
        var req = try self.client.open(.GET, uri, .{
            .server_header_buffer = .{ .allocator = self.allocator },
        });
        defer req.deinit();

        try req.send();
        try req.wait();
        return try req.reader().readAllAlloc(self.allocator, std.math.maxInt(usize));
    }

    pub fn getBlock(self: *TrustlessGateway, cid_str: []const u8) ![]u8 {
        const url = try std.fmt.allocPrint(self.allocator, "{s}/ipfs/{s}?format=raw", .{
            self.gateway_url,
            cid_str,
        });
        defer self.allocator.free(url);

        const uri = try std.Uri.parse(url);
        var req = try self.client.open(.GET, uri, .{
            .server_header_buffer = .{ .allocator = self.allocator },
        });
        defer req.deinit();

        try req.send();
        try req.wait();
        return try req.reader().readAllAlloc(self.allocator, std.math.maxInt(usize));
    }
};

pub const DNSLink = struct {
    allocator: std.mem.Allocator,
    gateway: GatewayClient,

    pub fn init(allocator: std.mem.Allocator, gateway_url: []const u8) DNSLink {
        return .{
            .allocator = allocator,
            .gateway = GatewayClient.init(allocator, gateway_url),
        };
    }

    pub fn deinit(self: *DNSLink) void {
        self.gateway.deinit();
    }

    pub fn resolve(self: *DNSLink, domain: []const u8, path: ?[]const u8) ![]u8 {
        const url = try std.fmt.allocPrint(self.allocator, "{s}/ipns/{s}", .{
            self.gateway.base_url,
            domain,
        });
        defer self.allocator.free(url);

        if (path) |p| {
            self.allocator.free(url);
            const url2 = try std.fmt.allocPrint(self.allocator, "{s}/ipns/{s}/{s}", .{
                self.gateway.base_url,
                domain,
                p,
            });
            return url2;
        }
        return url;
    }
};
