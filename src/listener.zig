// listener.zig
//
// Phase B listener skeleton (SPEC.md section 0.4, daemon milestone).
// Surface: pre-authentication. It receives attacker datagrams before any
// session exists, so BE-SURF-03 budgets it in the listener sub-unit (cap
// 250 lines, SPEC v0.3.6-draft). Zero Noise, zero handshake here: this
// module binds exactly one address family per socket (BE-EXEC-03),
// enforces one listener per endpoint (BE-EXEC-02), and receives datagrams
// into caller buffers. The handshake machinery (mac.zig, noise.zig) is
// wired on top in phase B2.
//
// Socket layer: Zig 0.16 moved high-level networking into std.Io.net,
// which requires an Io event-loop runtime. Phase B1 deliberately stays
// flat instead: five libc calls declared below (exactly as std.c itself
// declares them), explicit sockaddr layouts, no runtime dependency. Flat
// is auditable, deterministic, and what BE-DEP-01 asks for.

const std = @import("std");
const builtin = @import("builtin");

const libc = struct {
    extern "c" fn socket(domain: c_uint, sock_type: c_uint, protocol: c_uint) c_int;
    extern "c" fn bind(fd: c_int, addr: [*]const u8, addrlen: c_uint) c_int;
    extern "c" fn recvfrom(fd: c_int, buf: [*]u8, len: usize, flags: c_int, src_addr: ?*anyopaque, addrlen: ?*c_uint) isize;
    extern "c" fn close(fd: c_int) c_int;
};

// Stable kernel ABI on both macOS and Linux.
const AF_INET: u32 = 2;
const AF_INET6: u32 = if (builtin.os.tag == .linux) 10 else 30;
const SOCK_DGRAM: u32 = 2;

pub const Family = enum { ipv4, ipv6 };

pub const ListenError = error{
    EndpointBusy, // BE-EXEC-02: a listener already owns this endpoint
    FamilyMismatch, // BE-EXEC-03: address bytes do not match the socket's family
    BindRefused, // the OS refused the bind (endpoint owned outside this daemon)
    SocketFailed,
    RecvFailed,
};

pub const MAX_ENDPOINTS: usize = 8;

pub const Endpoint = struct {
    addr: [16]u8 = undefined, // family-sized octets of the bound address
    addr_len: usize = 0,
    port: u16 = 0,
};

// EndpointRegistry (BE-EXEC-02): one listener per (address, port). The
// registry is the daemon's ownership fact; the OS bind result is the second
// witness. Both must agree or the bind is refused. There is no third state.
pub const EndpointRegistry = struct {
    entries: [MAX_ENDPOINTS]Endpoint = undefined,
    count: usize = 0,

    pub fn owns(self: *const EndpointRegistry, addr: []const u8, port: u16) bool {
        for (self.entries[0..self.count]) |e| {
            if (e.port == port and e.addr_len == addr.len and
                std.mem.eql(u8, e.addr[0..e.addr_len], addr)) return true;
        }
        return false;
    }

    pub fn claim(self: *EndpointRegistry, addr: []const u8, port: u16) error{EndpointBusy}!void {
        if (self.owns(addr, port)) return error.EndpointBusy;
        if (self.count >= MAX_ENDPOINTS) return error.EndpointBusy;
        const e = &self.entries[self.count];
        @memcpy(e.addr[0..addr.len], addr);
        e.addr_len = addr.len;
        e.port = port;
        self.count += 1;
    }

    pub fn release(self: *EndpointRegistry, addr: []const u8, port: u16) void {
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            const e = self.entries[i];
            if (e.port == port and e.addr_len == addr.len and
                std.mem.eql(u8, e.addr[0..e.addr_len], addr))
            {
                self.entries[i] = self.entries[self.count - 1];
                self.count -= 1;
                return;
            }
        }
    }
};

pub const Listener = struct {
    fd: c_int = -1,
    family: Family = .ipv4,
    bound: bool = false,

    // open (BE-EXEC-03): the socket is created for exactly one address
    // family. No dual-stack option is set, ever.
    pub fn open(family: Family) ListenError!Listener {
        const af: u32 = switch (family) {
            .ipv4 => AF_INET,
            .ipv6 => AF_INET6,
        };
        const fd = libc.socket(af, SOCK_DGRAM, 0);
        if (fd < 0) return error.SocketFailed;
        return .{ .fd = fd, .family = family };
    }

    // bind (BE-EXEC-02, BE-EXEC-03): claim the endpoint in the registry,
    // then bind the OS socket. If the OS refuses, the claim is rolled back:
    // the registry never says owned for an endpoint the socket does not hold.
    pub fn bind(self: *Listener, registry: *EndpointRegistry, addr: []const u8, port: u16) ListenError!void {
        if (self.bound) return error.EndpointBusy;
        const want_len: usize = switch (self.family) {
            .ipv4 => 4,
            .ipv6 => 16,
        };
        if (addr.len != want_len) return error.FamilyMismatch;
        registry.claim(addr, port) catch return error.EndpointBusy;
        var sa: [28]u8 = undefined;
        const sa_len = makeSockaddr(self.family, addr, port, &sa);
        if (libc.bind(self.fd, &sa, sa_len) != 0) {
            registry.release(addr, port);
            return error.BindRefused;
        }
        self.bound = true;
    }

    // recv: one datagram into the caller's buffer. The caller owns the
    // bytes from here; parsing is the bound handshake machinery's job (B2).
    pub fn recv(self: *Listener, buf: []u8) ListenError!usize {
        const rc = libc.recvfrom(self.fd, buf.ptr, buf.len, 0, null, null);
        if (rc < 0) return error.RecvFailed;
        return @intCast(rc);
    }

    pub fn close(self: *Listener) void {
        if (self.fd >= 0) _ = libc.close(self.fd);
        self.fd = -1;
        self.bound = false;
    }
};

// makeSockaddr: flat sockaddr construction, explicit layouts. BSD-family
// (macOS) carries an sa_len byte first; Linux starts with the u16 family.
// Port is big-endian in both. Returns the sockaddr length to pass to bind.
fn makeSockaddr(family: Family, addr: []const u8, port: u16, out: *[28]u8) c_uint {
    out.* = .{0} ** 28;
    const af: u8 = switch (family) {
        .ipv4 => @intCast(AF_INET),
        .ipv6 => @intCast(AF_INET6),
    };
    const sa_len: c_uint = switch (family) {
        .ipv4 => 16,
        .ipv6 => 28,
    };
    switch (builtin.os.tag) {
        .macos, .freebsd, .openbsd, .netbsd, .dragonfly => {
            out[0] = @intCast(sa_len);
            out[1] = af;
        },
        else => {
            out[0] = af;
            out[1] = 0;
        },
    }
    out[2] = @intCast(port >> 8);
    out[3] = @intCast(port & 0xff);
    switch (family) {
        // ipv4: address at bytes 4..8.
        .ipv4 => @memcpy(out[4..8], addr[0..4]),
        // ipv6: flowinfo 4..8 stays zero, address at 8..24, scope 24..28 zero.
        .ipv6 => @memcpy(out[8..24], addr[0..16]),
    }
    return sa_len;
}
