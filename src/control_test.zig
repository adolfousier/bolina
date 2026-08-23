// control_test.zig
//
// D-091 P1 tests: the control-plane state machine over REAL loopback
// sockets. Every test drives pollPass laps with explicit timestamps, so
// there are no sleeps and no flaky waits: a lap returns instantly whenever
// bytes are already queued, and deadline laps pass now >= deadline so the
// timeout computes to zero. The daemon slot is null in every test here;
// the wire-path integration lives in pilot_test (unchanged) and the main.zig
// wiring smoke.
//
// Accept is one connection per lap (one accept syscall per POLLIN event),
// so tests that fill the table run one lap per pending client.

const std = @import("std");
const ctl = @import("control.zig");
const hp = @import("http_parse.zig");
const token_mod = @import("token.zig");

const libc = struct {
    extern "c" fn socket(domain: c_uint, sock_type: c_uint, protocol: c_uint) c_int;
    extern "c" fn connect(fd: c_int, addr: [*]const u8, addrlen: c_uint) c_int;
    extern "c" fn send(fd: c_int, buf: [*]const u8, len: usize, flags: c_int) isize;
    extern "c" fn recv(fd: c_int, buf: [*]u8, len: usize, flags: c_int) isize;
    extern "c" fn close(fd: c_int) c_int;
    extern "c" fn getsockname(fd: c_int, addr: [*]u8, addrlen: *c_uint) c_int;
    extern "c" fn fcntl(fd: c_int, cmd: c_int, arg: c_int) c_int;
    extern "c" fn nanosleep(req: *const Ts, rem: ?*Ts) c_int;
};

const Ts = extern struct { sec: c_long, nsec: c_long };

// recvWait: bounded wait for data or EOF on a non-blocking client fd.
// Loopback answers are near-instant but the FIN/data wakeup is not
// synchronous with the server's syscall; 100 x 1ms is the ceiling so a
// broken server fails fast instead of hanging or flaking.
fn recvWait(fd: c_int, buf: []u8) isize {
    const one_ms = Ts{ .sec = 0, .nsec = 1_000_000 };
    var rem: Ts = undefined;
    var tries: usize = 0;
    while (tries < 100) : (tries += 1) {
        const n = libc.recv(fd, buf.ptr, buf.len, 0);
        if (n != -1) return n; // bytes or clean EOF
        _ = libc.nanosleep(&one_ms, &rem);
    }
    return -1;
}

const AF_INET: u32 = 2;
const SOCK_STREAM: u32 = 1;
const F_SETFL: c_int = 4;
const O_NONBLOCK: c_int = 0o4000; // same value on macOS and Linux

const T0: u64 = 10_000; // arbitrary test epoch, ms

// Process-global token fixture: Control.token_hex must outlive setup()'s
// return-by-value copy of Harness, so it aliases this static, never h.token
// (a dangling stack pointer that only the happy-path test would expose).
var fixture_token: [token_mod.TOKEN_HEX_LEN]u8 = undefined;

// Harness: one Control on an ephemeral loopback port plus one connected
// client fd. Laps run through pollPass exactly as production does.
const Harness = struct {
    node: *ctl.Control,
    client: c_int,
    port: u16,
    token: [token_mod.TOKEN_HEX_LEN]u8,

    fn setup() !Harness {
        var h = Harness{
            .node = undefined,
            .client = -1,
            .port = 0,
            .token = undefined,
        };
        @memset(&h.token, 'a'); // "aa..a": valid hex, 64 chars
        @memset(&fixture_token, 'a');
        const addr = [4]u8{ 127, 0, 0, 1 };
        h.node = try ctl.Control.init(&addr, 0, &fixture_token);
        var sa: [16]u8 = undefined;
        var sa_len: c_uint = 16;
        if (libc.getsockname(h.node.listen_fd, &sa, &sa_len) != 0) return error.NoPort;
        h.port = (@as(u16, sa[2]) << 8) | sa[3];
        h.client = connectTo(h.port);
        if (h.client < 0) return error.ConnectFailed;
        return h;
    }

    fn lap(self: *Harness, now_ms: u64) void {
        var dgram: [8]u8 = undefined;
        var sa: [4]u8 = undefined;
        var sa_len: c_uint = 4;
        self.node.pollPass(null, -1, now_ms, &dgram, &sa, &sa_len);
    }

    // write + two laps: lap 1 accepts the connection into a slot, lap 2 runs
    // that slot through parse and answer (write-through on full response).
    fn roundTrip(self: *Harness, req: []const u8, now_ms: u64) void {
        _ = libc.send(self.client, req.ptr, req.len, 0);
        // Two laps: lap 1 accepts the connection into a slot, lap 2 runs
        // that slot through parse and answer (a fresh fd joins the poll set
        // only on the pass after its accept).
        self.lap(now_ms);
        self.lap(now_ms);
    }

    // freshClient: every HTTP request needs its own connection (the server
    // always answers Connection: close). Reusing a closed fd would SIGPIPE.
    fn freshClient(self: *Harness) void {
        _ = libc.close(self.client);
        self.client = connectTo(self.port);
    }

    // readResponse: recv until the full head+body message is in hand or the
    // peer closes. Parses Content-Length out of the head to know when to stop.
    fn readResponse(self: *Harness, buf: []u8) usize {
        var total: usize = 0;
        while (total < buf.len) {
            const n = libc.recv(self.client, buf.ptr + total, buf.len - total, 0);
            if (n <= 0) break; // EOF after Connection: close
            total += @intCast(n);
            const term = std.mem.indexOf(u8, buf[0..total], "\r\n\r\n") orelse continue;
            const clen_line = std.mem.indexOf(u8, buf[0..total], "Content-Length: ") orelse break;
            const vstart = clen_line + "Content-Length: ".len;
            const vend = std.mem.indexOfPos(u8, buf[0..total], vstart, "\r\n") orelse break;
            const clen = std.fmt.parseInt(usize, buf[vstart..vend], 10) catch break;
            if (total >= term + 4 + clen) break; // whole message in hand
        }
        return total;
    }

    fn shutdown(self: *Harness) void {
        _ = libc.close(self.node.listen_fd);
        self.node.listen_fd = -1;
        for (&self.node.conns) |*c| {
            if (c.state != .idle) {
                _ = libc.close(c.fd);
                c.* = .{};
            }
        }
        _ = libc.close(self.client);
    }
};

fn connectTo(port: u16) c_int {
    const cfd = libc.socket(AF_INET, SOCK_STREAM, 0);
    if (cfd < 0) return -1;
    var csa: [16]u8 = .{0} ** 16;
    csa[0] = 16; // BSD sin_len; harmless zero on Linux
    csa[1] = 2;
    csa[2] = @intCast(port >> 8);
    csa[3] = @intCast(port & 0xff);
    csa[4..8].* = .{ 127, 0, 0, 1 };
    if (libc.connect(cfd, &csa, 16) != 0) {
        _ = libc.close(cfd);
        return -1;
    }
    // Non-blocking client side: a server that never answers turns into a
    // fast short read and a loud assert, never a blocked recv.
    _ = libc.fcntl(cfd, F_SETFL, O_NONBLOCK);
    return cfd;
}

test "P1 healthz answers 200 open, no token required" {
    var h = try Harness.setup();
    defer h.shutdown();
    h.roundTrip("GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n", T0);
    var buf: [512]u8 = undefined;
    const n = h.readResponse(&buf);
    try std.testing.expect(n > 0);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "HTTP/1.1 200 OK") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "bolina ok") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "Connection: close") != null);
    try std.testing.expectEqual(@as(u64, 1), h.node.requests_served);
}

test "P1 incremental delivery: three dribbles then completion" {
    var h = try Harness.setup();
    defer h.shutdown();
    const req = "GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n";
    _ = libc.send(h.client, req.ptr, 12, 0); // "GET /healthz"
    h.lap(T0); // lap 1: accepted into a reading slot
    try std.testing.expectEqual(ctl.ConnState.reading, h.node.conns[0].state);
    h.lap(T0); // lap 2: parsed, Incomplete, nothing answered yet
    try std.testing.expectEqual(ctl.ConnState.reading, h.node.conns[0].state);
    try std.testing.expectEqual(@as(u64, 0), h.node.requests_served);
    _ = libc.send(h.client, req.ptr + 12, 20, 0);
    h.lap(T0 + 100); // still short of the terminator
    try std.testing.expectEqual(ctl.ConnState.reading, h.node.conns[0].state);
    _ = libc.send(h.client, req.ptr + 32, req.len - 32, 0);
    h.lap(T0 + 200); // complete: parsed, answered, closed in this lap
    var buf: [256]u8 = undefined;
    const n = h.readResponse(&buf);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "200 OK") != null);
}

test "P1 slowloris: idle past deadline is swept closed without a reply" {
    var h = try Harness.setup();
    defer h.shutdown();
    _ = libc.send(h.client, "GET /healthz HTTP/1.", 20, 0);
    h.lap(T0); // accept
    h.lap(T0); // read the partial head: Incomplete, slot held
    try std.testing.expectEqual(ctl.ConnState.reading, h.node.conns[0].state);
    h.lap(T0 + ctl.CONN_TIMEOUT_MS + 1); // deadline lap: sweep closes silently
    try std.testing.expectEqual(ctl.ConnState.idle, h.node.conns[0].state);
    try std.testing.expectEqual(@as(u64, 1), h.node.timeouts);
    var buf: [64]u8 = undefined;
    const n = recvWait(h.client, &buf);
    try std.testing.expectEqual(@as(isize, 0), n); // clean EOF, zero bytes sent
}

test "P1 chunked transfer encoding is refused with 501, explicitly" {
    var h = try Harness.setup();
    defer h.shutdown();
    h.roundTrip("POST /v1/x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", T0);
    var buf: [256]u8 = undefined;
    const n = h.readResponse(&buf);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "501 Not Implemented") != null);
}

test "P1 header block without a terminator inside the cap dies 400" {
    var h = try Harness.setup();
    defer h.shutdown();
    var req_buf: [hp.HEADER_CAP]u8 = undefined;
    // Exactly HEADER_CAP bytes with no \r\n\r\n anywhere: HeadersTooLarge
    // fires at the size gate, before any deadline could.
    @memset(&req_buf, 'y');
    const prefix = "GET / HTTP/1.1\r\nX-Pad: ";
    @memcpy(req_buf[0..prefix.len], prefix);
    _ = libc.send(h.client, req_buf[0..], hp.HEADER_CAP, 0);
    h.lap(T0); // accept
    h.lap(T0); // read: parser refuses at the size gate
    var buf: [256]u8 = undefined;
    const n = h.readResponse(&buf);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "400 Bad Request") != null);
}

test "P1 auth gate: 403 missing, 403 wrong, valid reaches routing (404)" {
    var h = try Harness.setup();
    defer h.shutdown();
    var buf: [256]u8 = undefined;

    h.roundTrip("GET /v1/x HTTP/1.1\r\nHost: x\r\n\r\n", T0);
    var n = h.readResponse(&buf);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "403 Forbidden") != null);
    h.freshClient();

    var wrong: [token_mod.TOKEN_HEX_LEN]u8 = undefined;
    @memset(&wrong, 'f');
    var req_buf: [200]u8 = undefined;
    const wrong_req = std.fmt.bufPrint(&req_buf, "GET /v1/x HTTP/1.1\r\nAuthorization: Bearer {s}\r\n\r\n", .{wrong}) catch unreachable;
    h.roundTrip(wrong_req, T0);
    n = h.readResponse(&buf);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "403 Forbidden") != null);
    h.freshClient();

    const good_req = std.fmt.bufPrint(&req_buf, "GET /v1/x HTTP/1.1\r\nAuthorization: Bearer {s}\r\n\r\n", .{h.token}) catch unreachable;
    h.roundTrip(good_req, T0);
    n = h.readResponse(&buf);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "404 Not Found") != null);
    try std.testing.expectEqual(@as(u64, 2), h.node.auth_refused);
}

test "P1 POST without Content-Length is 400 (LengthRequired mapping)" {
    var h = try Harness.setup();
    defer h.shutdown();
    h.roundTrip("POST /v1/intents HTTP/1.1\r\nHost: x\r\n\r\n", T0);
    var buf: [256]u8 = undefined;
    const n = h.readResponse(&buf);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "400 Bad Request") != null);
}

test "P1 full table: the overflowing connection reads 503, none evicted" {
    var h = try Harness.setup();
    defer h.shutdown();
    // h.client plus seven more occupy all eight slots (half-sent requests
    // keep every slot in reading); one extra then overflows the table.
    var others: [ctl.MAX_CONNS - 1]c_int = undefined;
    _ = libc.send(h.client, "GET /healthz HTT", 16, 0); // half request
    for (&others) |*c| {
        c.* = connectTo(h.port);
        try std.testing.expect(c.* >= 0);
        _ = libc.send(c.*, "GET /healthz HTT", 16, 0);
    }
    // One accept per lap: eight laps drain the backlog into the eight slots.
    for (0..ctl.MAX_CONNS) |i| h.lap(T0 + i);
    for (&h.node.conns) |*c| try std.testing.expectEqual(ctl.ConnState.reading, c.state);

    const extra = connectTo(h.port);
    try std.testing.expect(extra >= 0);
    _ = libc.send(extra, "GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n", 35, 0);
    h.lap(T0 + 99); // accept fires, table full: 503 + close, no eviction
    var buf: [128]u8 = undefined;
    const n = recvWait(extra, &buf);
    try std.testing.expect(n > 0);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..@intCast(n)], "503 Service Unavailable") != null);
    _ = libc.close(extra); // FIN timing vs non-blocking recv is a race; not asserted
    try std.testing.expectEqual(@as(u64, 1), h.node.rejects_503);

    // No eviction: every slot still reading, and h.client still completes.
    for (&h.node.conns) |*c| try std.testing.expectEqual(ctl.ConnState.reading, c.state);
    _ = libc.send(h.client, "P/1.1\r\nHost: x\r\n\r\n", 18, 0);
    h.lap(T0 + 100);
    const done = recvWait(h.client, &buf);
    try std.testing.expect(done > 0);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..@intCast(done)], "200 OK") != null);
}
