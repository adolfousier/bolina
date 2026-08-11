// listener_test.zig
//
// Phase B B1 binding tests (SPEC.md section 0.4): BE-EXEC-02 one listener
// per endpoint, BE-EXEC-03 single address family. Literal values throughout
// (D-027), real loopback UDP sockets: the socket layer is exactly what this
// slice falsifies, so a fake transport would falsify nothing.

const std = @import("std");
const builtin = @import("builtin");
const listener_mod = @import("listener.zig");

// Sender-side socket calls for the probe test. Declared here, not in
// listener.zig: B1's surface is bind and receive only.
extern "c" fn socket(domain: c_uint, sock_type: c_uint, protocol: c_uint) c_int;
extern "c" fn sendto(fd: c_int, buf: [*]const u8, len: usize, flags: c_int, dest_addr: [*]const u8, addrlen: c_uint) isize;
extern "c" fn close(fd: c_int) c_int;
extern "c" fn getsockname(fd: c_int, addr: [*]u8, addrlen: *c_uint) c_int;

const LOOPBACK_V4 = [4]u8{ 127, 0, 0, 1 };
const LOOPBACK_V6 = [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
const PORT_BUSY: u16 = 45671;
const PORT_V6: u16 = 45672;
const PORT_PROBE: u16 = 45673;
const PROBE = "bolina-phase-b1-probe";

fn v4Sockaddr(addr: [4]u8, port: u16) [16]u8 {
    var out: [16]u8 = .{0} ** 16;
    switch (builtin.os.tag) {
        .macos, .freebsd, .openbsd, .netbsd, .dragonfly => {
            out[0] = 16; // sa_len
            out[1] = 2; // AF_INET
        },
        else => {
            out[0] = 2; // sa_family, little-endian low byte
            out[1] = 0;
        },
    }
    out[2] = @intCast(port >> 8);
    out[3] = @intCast(port & 0xff);
    out[4] = addr[0];
    out[5] = addr[1];
    out[6] = addr[2];
    out[7] = addr[3];
    return out;
}

test "BE_EXEC_02 registry owns endpoints one listener at a time" {
    var reg = listener_mod.EndpointRegistry{};
    try reg.claim(&LOOPBACK_V4, PORT_BUSY);
    try std.testing.expect(reg.owns(&LOOPBACK_V4, PORT_BUSY));
    try std.testing.expectError(error.EndpointBusy, reg.claim(&LOOPBACK_V4, PORT_BUSY));
    // a different port on the same address stays free
    try std.testing.expect(!reg.owns(&LOOPBACK_V4, PORT_BUSY + 1));
    reg.release(&LOOPBACK_V4, PORT_BUSY);
    try std.testing.expect(!reg.owns(&LOOPBACK_V4, PORT_BUSY));
    // a released endpoint can be claimed again
    try reg.claim(&LOOPBACK_V4, PORT_BUSY);
}

test "BE_EXEC_02 second bind on the same endpoint is refused" {
    var reg = listener_mod.EndpointRegistry{};
    var a = try listener_mod.Listener.open(.ipv4);
    defer a.close();
    try a.bind(&reg, &LOOPBACK_V4, PORT_BUSY);
    // second listener, same daemon registry: refused by ownership
    var b = try listener_mod.Listener.open(.ipv4);
    defer b.close();
    try std.testing.expectError(listener_mod.ListenError.EndpointBusy, b.bind(&reg, &LOOPBACK_V4, PORT_BUSY));
    // rebinding the owning listener is also refused: one bind per listener
    try std.testing.expectError(listener_mod.ListenError.EndpointBusy, a.bind(&reg, &LOOPBACK_V4, PORT_BUSY));
}

test "BE_EXEC_02 OS refuses a duplicate bind outside the registry" {
    var reg_a = listener_mod.EndpointRegistry{};
    var reg_b = listener_mod.EndpointRegistry{};
    var a = try listener_mod.Listener.open(.ipv4);
    defer a.close();
    try a.bind(&reg_a, &LOOPBACK_V4, PORT_BUSY + 10);
    // fresh registry with no ownership knowledge: the OS is the witness
    var b = try listener_mod.Listener.open(.ipv4);
    defer b.close();
    try std.testing.expectError(listener_mod.ListenError.BindRefused, b.bind(&reg_b, &LOOPBACK_V4, PORT_BUSY + 10));
    // the failed bind rolled its claim back: the registry never lies
    try std.testing.expect(!reg_b.owns(&LOOPBACK_V4, PORT_BUSY + 10));
}

test "BE_EXEC_03 a listener binds exactly one address family" {
    var reg = listener_mod.EndpointRegistry{};
    var v4 = try listener_mod.Listener.open(.ipv4);
    defer v4.close();
    // wrong-family address bytes are refused before any OS call
    try std.testing.expectError(listener_mod.ListenError.FamilyMismatch, v4.bind(&reg, &LOOPBACK_V6, PORT_V6));
    try v4.bind(&reg, &LOOPBACK_V4, PORT_V6);
    // the IPv6 socket is a second socket, never the same one in dual-stack
    var v6 = try listener_mod.Listener.open(.ipv6);
    defer v6.close();
    try std.testing.expectError(listener_mod.ListenError.FamilyMismatch, v6.bind(&reg, &LOOPBACK_V4, PORT_V6 + 1));
    try v6.bind(&reg, &LOOPBACK_V6, PORT_V6 + 1);
}

test "BE_EXEC_03 datagrams flow through the bound listener" {
    var reg = listener_mod.EndpointRegistry{};
    var l = try listener_mod.Listener.open(.ipv4);
    defer l.close();
    try l.bind(&reg, &LOOPBACK_V4, PORT_PROBE);
    const sender = socket(2, 2, 0);
    try std.testing.expect(sender >= 0);
    defer _ = close(sender);
    const sa = v4Sockaddr(LOOPBACK_V4, PORT_PROBE);
    const sa_len: c_uint = 16;
    const sent = sendto(sender, PROBE, PROBE.len, 0, &sa, sa_len);
    try std.testing.expectEqual(@as(isize, PROBE.len), sent);
    var buf: [64]u8 = undefined;
    const n = try l.recv(&buf);
    try std.testing.expectEqual(PROBE.len, n);
    try std.testing.expectEqualStrings(PROBE, buf[0..n]);
}

test "BE_EXEC_03 the created socket carries exactly the declared family" {
    // Inspect the created sockets: BE-EXEC-03 forbids a socket pretending to
    // a family it was not created with (the dual-stack leak). getsockname on
    // an unbound socket still reports its real domain.
    var l4 = try listener_mod.Listener.open(.ipv4);
    defer l4.close();
    var sa4: [28]u8 = undefined;
    var len4: c_uint = 28;
    _ = getsockname(l4.fd, &sa4, &len4);
    const fam4: u8 = switch (builtin.os.tag) {
        .macos, .freebsd, .openbsd, .netbsd, .dragonfly => sa4[1],
        else => sa4[0],
    };
    try std.testing.expectEqual(@as(u8, 2), fam4); // AF_INET, nothing else
    var l6 = try listener_mod.Listener.open(.ipv6);
    defer l6.close();
    var sa6: [28]u8 = undefined;
    var len6: c_uint = 28;
    _ = getsockname(l6.fd, &sa6, &len6);
    const fam6: u8 = switch (builtin.os.tag) {
        .macos, .freebsd, .openbsd, .netbsd, .dragonfly => sa6[1],
        else => sa6[0],
    };
    try std.testing.expect(fam6 != 2); // an ipv6 socket, never AF_INET
}
