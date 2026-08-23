// control.zig
//
// D-091 P1: the v0.6 local control plane. One optional TCP listener on
// loopback (opt-in via BOLINA_CONTROL, default 127.0.0.1:7421) serving an
// HTTP/1.1 subset over fixed bounds, zero heap, zero threads, so any
// language with a stdlib HTTP client can drive the node without touching
// the protocol wire. Applications never speak UDP; this plane is the only
// surface they see, and it is additive forever (/v1/ never breaks).
//
// Concurrency model (postmortem F1, constraint P0): ONE poll() multiplexes
// the UDP wire fd (slot 0), the TCP listen fd (slot 1) and up to 8 client
// connections (slots 2..9). The wire path calls daemon.handleDatagram byte
// for byte like main.zig's plain loop; without BOLINA_CONTROL the process
// never constructs a Control and the pilot e2e path is unchanged. There is
// no thread anywhere and no lock anywhere: single-threaded by construction.
//
// Fail-closed posture carried over from the daemon: unparseable requests
// answer 4xx/5xx and close, the connection table full answers 503 and
// closes (refuse-new keep-existing, every other fixed bound's shape),
// deadlines close silently (slowloris dies on size in the parser and on
// time here as the second gate), and everything but /healthz demands the
// bearer token. Auth failures count and answer 403 without echoing what
// was wrong.
//
// Anti god-mode (D-091 hard rule): routes call the SAME dispatch/ledger
// functions the transport path uses. No endpoint mutates grants or the
// ledger directly; P2 endpoints are facades, nothing more.

const std = @import("std");
const builtin = @import("builtin");
const control_api = @import("control_api.zig");
const channel = @import("parser/channel.zig");
const http_parse = @import("http_parse.zig");
const token_mod = @import("token.zig");
const daemon_mod = @import("daemon.zig");

pub const ControlError = error{
    SocketFailed,
    BindRefused, // EADDRINUSE or refused: fatal at boot, pairs with the wire listener's rule
    ListenFailed,
};

const libc = struct {
    extern "c" fn socket(domain: c_uint, sock_type: c_uint, protocol: c_uint) c_int;
    extern "c" fn setsockopt(fd: c_int, level: c_int, optname: c_int, optval: [*]const u8, optlen: c_uint) c_int;
    extern "c" fn bind(fd: c_int, addr: [*]const u8, addrlen: c_uint) c_int;
    extern "c" fn listen(fd: c_int, backlog: c_int) c_int;
    extern "c" fn accept(fd: c_int, addr: ?*anyopaque, addrlen: ?*c_uint) c_int;
    extern "c" fn recv(fd: c_int, buf: [*]u8, len: usize, flags: c_int) isize;
    extern "c" fn send(fd: c_int, buf: [*]const u8, len: usize, flags: c_int) isize;
    extern "c" fn close(fd: c_int) c_int;
    extern "c" fn poll(fds: [*]PollFd, nfds: c_ulong, timeout: c_int) c_int;
    extern "c" fn recvfrom(fd: c_int, buf: [*]u8, len: usize, flags: c_int, src_addr: ?*anyopaque, addrlen: ?*c_uint) isize;
};

// pollfd + events: identical layout and bit values on macOS and Linux.
pub const PollFd = extern struct { fd: c_int, events: i16, revents: i16 };
const POLLIN: i16 = 0x001;
const POLLOUT: i16 = 0x004;
const POLLERR: i16 = 0x008;
const POLLHUP: i16 = 0x010;

// SO_REUSEADDR/SOL_SOCKET differ numerically across BSD and Linux; both are
// pinned per OS so a restart inside TIME_WAIT does not wedge the port.
const SOL_SOCKET: c_int = if (builtin.os.tag == .macos) 0xffff else 1;
const SO_REUSEADDR: c_int = if (builtin.os.tag == .macos) 4 else 2;
const IPPROTO_TCP: c_int = 6; // same on both
const TCP_NODELAY: c_int = 1; // same on both
const AF_INET: u32 = 2;
const SOCK_STREAM: u32 = 1;

pub const MAX_CONNS: usize = 8;
pub const CONN_TIMEOUT_MS: u64 = 5000;
// Request buffer per connection: parser caps are the contract (8KB headers,
// 64KB body). Fixed storage, no allocation, ever.
const CONN_BUF_CAP: usize = http_parse.HEADER_CAP + http_parse.BODY_CAP;
const WRITE_CAP: usize = 16384;
const IDLE_POLL_MS: c_int = 1000; // keeps the shutdown flag responsive

// makeSockaddrIn: flat IPv4 TCP sockaddr, explicit BSD/Linux split, same
// shape as listener.zig's datagram builder.
fn makeSockaddrIn(addr: *const [4]u8, port: u16, out: *[16]u8) c_uint {
    out.* = .{0} ** 16;
    const sa_len: c_uint = 16;
    const bsd = switch (builtin.os.tag) {
        .macos, .freebsd, .openbsd, .netbsd, .dragonfly => true,
        else => false,
    };
    out[0] = if (bsd) @intCast(sa_len) else 2;
    out[1] = if (bsd) 2 else 0;
    out[2] = @intCast(port >> 8);
    out[3] = @intCast(port & 0xff);
    @memcpy(out[4..8], addr);
    return sa_len;
}

const State = enum { idle, reading, writing };
pub const ConnState = State; // seam for the dedicated test file

const Conn = struct {
    fd: c_int = -1,
    state: State = .idle,
    deadline_ms: u64 = 0,
    buf: [CONN_BUF_CAP]u8 = undefined,
    len: usize = 0,
    out: [WRITE_CAP]u8 = undefined,
    out_len: usize = 0,
    out_sent: usize = 0,
};

pub const Control = struct {
    listen_fd: c_int = -1,
    token_hex: *const [token_mod.TOKEN_HEX_LEN]u8,
    conns: [MAX_CONNS]Conn = undefined,
    // P2 (D-091): attached by main after both sides construct; null keeps
    // /v1/* answering 404 so control-only tests need no daemon pieces.
    api: ?*control_api.Api = null,
    // Single scratch for API response bodies: routing is single-threaded
    // and finishes before answerAndClose copies into the conn buffer.
    scratch: [WRITE_CAP]u8 = undefined,
    // Surfaced counters: /metrics reads these in P2; nothing blocks on them.
    requests_served: u64 = 0,
    auth_refused: u64 = 0,
    bad_requests: u64 = 0,
    rejects_503: u64 = 0,
    timeouts: u64 = 0,

    // init: TCP socket, REUSEADDR + NODELAY, bind, listen. Any refusal is
    // fatal at boot (the caller fatals on ControlError like on BindRefused
    // for the wire listener): half-up control planes are worse than none.
    pub fn init(addr: *const [4]u8, port: u16, token_hex: *const [token_mod.TOKEN_HEX_LEN]u8) ControlError!*Control {
        control_storage = .{ .token_hex = token_hex, .conns = undefined };
        for (&control_storage.conns) |*c| c.* = .{};
        const fd = libc.socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return error.SocketFailed;
        const one: c_int = 1;
        _ = libc.setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, std.mem.asBytes(&one), @sizeOf(c_int));
        _ = libc.setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, std.mem.asBytes(&one), @sizeOf(c_int));
        var sa: [16]u8 = undefined;
        const sa_len = makeSockaddrIn(addr, port, &sa);
        if (libc.bind(fd, &sa, sa_len) != 0) {
            _ = libc.close(fd);
            return error.BindRefused;
        }
        if (libc.listen(fd, MAX_CONNS) != 0) {
            _ = libc.close(fd);
            return error.ListenFailed;
        }
        control_storage.listen_fd = fd;
        return &control_storage;
    }

    // buildPollSet: slot 0 wire, slot 1 listen, slots 2..9 clients (idle
    // slots carry fd -1, which poll skips). Fixed order keeps the mapping
    // back to slots arithmetic instead of bookkeeping.
    fn fillPollSet(self: *Control, fds: *[2 + MAX_CONNS]PollFd, wire_fd: c_int) void {
        fds[0] = .{ .fd = wire_fd, .events = POLLIN, .revents = 0 };
        fds[1] = .{ .fd = self.listen_fd, .events = POLLIN, .revents = 0 };
        for (&self.conns, fds[2..]) |*c, *p| {
            const want: i16 = switch (c.state) {
                .idle => 0,
                .reading => POLLIN,
                .writing => POLLOUT,
            };
            p.* = .{ .fd = if (c.state == .idle) -1 else c.fd, .events = want, .revents = 0 };
        }
    }

    fn pollTimeout(self: *Control, now_ms: u64) c_int {
        var min: u64 = std.math.maxInt(u64);
        for (&self.conns) |*c| {
            if (c.state != .idle and c.deadline_ms < min) min = c.deadline_ms;
        }
        if (min == std.math.maxInt(u64)) return IDLE_POLL_MS;
        if (min <= now_ms) return 0;
        const rest = min - now_ms;
        return @intCast(@min(rest, @as(u64, IDLE_POLL_MS)));
    }

    // pollPass: one multiplexed iteration. The wire outranks the control
    // plane by evaluation order; handleDatagram is THE daemon entry point,
    // called exactly like the plain loop in main. A null daemon (tests)
    // skips the wire slot entirely: control-plane laps only.
    pub fn pollPass(self: *Control, d: ?*daemon_mod.Daemon, wire_fd: c_int, now_ms: u64, dgram_buf: []u8, sa: [*]u8, sa_len: *c_uint) void {
        var fds: [2 + MAX_CONNS]PollFd = undefined;
        self.fillPollSet(&fds, wire_fd);
        _ = libc.poll(&fds, 2 + MAX_CONNS, self.pollTimeout(now_ms));
        if (d != null and (fds[0].revents & (POLLIN | POLLERR)) != 0) {
            const n = libc.recvfrom(wire_fd, dgram_buf.ptr, dgram_buf.len, 0, sa, sa_len);
            if (n > 0) _ = d.?.handleDatagram(dgram_buf[0..@intCast(n)], sa, sa_len.*, now_ms);
        }
        if ((fds[1].revents & POLLIN) != 0) self.onAcceptable(now_ms);
        for (&self.conns, fds[2..]) |*c, *p| {
            if (c.state == .idle) continue;
            if ((p.revents & (POLLERR | POLLHUP)) != 0) {
                self.closeSlot(c);
                continue;
            }
            if ((p.revents & POLLIN) != 0 and c.state == .reading) self.onReadable(c, now_ms);
            if ((p.revents & POLLOUT) != 0 and c.state == .writing) self.onWritable(c);
        }
        self.sweepTimeouts(now_ms);
    }

    // runLoop: the shipped daemon loop when BOLINA_CONTROL is set. Exits
    // when the shutdown flag flips (SIGTERM/SIGINT handler in main), then
    // drains bounded (F9).
    pub fn runLoop(self: *Control, d: *daemon_mod.Daemon, wire_fd: c_int, shutdown: *const std.atomic.Value(bool), nowMs: *const fn () u64) void {
        var dgram: [2048]u8 = undefined;
        var sa: [28]u8 = undefined;
        var sa_len: c_uint = 28;
        while (!shutdown.load(.monotonic)) {
            self.pollPass(d, wire_fd, nowMs(), &dgram, &sa, &sa_len);
            sa_len = 28;
        }
        self.drain();
    }
    // drain (F9): stop accepting, one best-effort flush pass for writers,
    // then close everything. The ledger needs no flush call (every commit
    // already fsynced inside grant_ledger); the bound is one pass, not a wait.
    fn drain(self: *Control) void {
        _ = libc.close(self.listen_fd);
        self.listen_fd = -1;
        for (&self.conns) |*c| {
            if (c.state == .writing and c.out_sent < c.out_len) {
                const n = libc.send(c.fd, c.out[c.out_sent..].ptr, c.out_len - c.out_sent, 0);
                if (n > 0) c.out_sent += @intCast(n);
            }
            self.closeSlot(c);
        }
    }

    // onAcceptable: accept one pending connection. A full table answers 503
    // and closes immediately: refuse-new keep-existing, no eviction ever.
    fn onAcceptable(self: *Control, now_ms: u64) void {
        const fd = libc.accept(self.listen_fd, null, null);
        if (fd < 0) return;
        for (&self.conns) |*c| {
            if (c.state != .idle) continue;
            const one: c_int = 1;
            _ = libc.setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, std.mem.asBytes(&one), @sizeOf(c_int));
            c.* = .{ .fd = fd, .state = .reading, .deadline_ms = now_ms + CONN_TIMEOUT_MS };
            return;
        }
        self.rejects_503 += 1;
        var scratch: [96]u8 = undefined;
        const msg = formatStatus(&scratch, 503, "service unavailable\n");
        _ = libc.send(fd, msg.ptr, msg.len, 0);
        _ = libc.close(fd);
    }

    // onReadable: append bytes, refresh the deadline, advance the parse.
    // recv <= 0 closes either way (EOF or dead fd): fail-closed beats spin.
    fn onReadable(self: *Control, c: *Conn, now_ms: u64) void {
        const n = libc.recv(c.fd, c.buf[c.len..].ptr, c.buf.len - c.len, 0);
        if (n <= 0) {
            self.closeSlot(c);
            return;
        }
        c.len += @intCast(n);
        c.deadline_ms = now_ms + CONN_TIMEOUT_MS;
        // Slowloris dribble guard: headers must show a newline within the
        // first kilobyte or the request dies now, not at the deadline.
        if (std.mem.indexOfScalar(u8, c.buf[0..c.len], '\n') == null and c.len >= 1024) {
            self.bad_requests += 1;
            self.answerAndClose(c, .{ .status = 400, .body = "bad request\n", .content_type = "text/plain" });
            return;
        }
        const req = http_parse.parse(c.buf[0..c.len]) catch |e| switch (e) {
            error.Incomplete => {
                if (c.len >= c.buf.len) { // unreachable via caps, kept honest
                    self.closeSlot(c);
                }
                return;
            },
            else => {
                self.bad_requests += 1;
                self.answerAndClose(c, statusRoute(e));
                return;
            },
        };
        self.answerAndClose(c, self.routeRequest(req, c.buf[req.body_start..][0..req.content_length], now_ms));
    }

    fn onWritable(self: *Control, c: *Conn) void {
        const n = libc.send(c.fd, c.out[c.out_sent..].ptr, c.out_len - c.out_sent, 0);
        if (n <= 0) {
            self.closeSlot(c);
            return;
        }
        c.out_sent += @intCast(n);
        if (c.out_sent >= c.out_len) self.closeSlot(c); // Connection: close, always
    }

    fn sweepTimeouts(self: *Control, now_ms: u64) void {
        for (&self.conns) |*c| {
            if (c.state != .idle and now_ms >= c.deadline_ms) {
                self.timeouts += 1;
                self.closeSlot(c); // silent close is valid (section 11.2)
            }
        }
    }

    fn closeSlot(self: *Control, c: *Conn) void {
        _ = self;
        if (c.fd >= 0) _ = libc.close(c.fd);
        c.* = .{};
    }

    // routeRequest: /healthz open (F7), everything else behind the bearer
    // token. Unknown paths under a VALID token read 404, never silence.
    // P2: /v1/* delegates to the Api facade when one is attached (D-091);
    // with no Api attached every /v1/* route stays 404.
    fn routeRequest(self: *Control, req: http_parse.Request, body: []const u8, now_ms: u64) Route {
        if (req.method == .get and std.mem.eql(u8, req.target, "/healthz"))
            return .{ .status = 200, .body = "bolina ok\n", .content_type = "text/plain" };
        const tok = bearerValue(req.authorization) orelse {
            self.auth_refused += 1;
            return forbidden_route;
        };
        if (!token_mod.verify(tok, self.token_hex)) {
            self.auth_refused += 1;
            return forbidden_route;
        }
        if (self.api) |api| {
            if (req.method == .get and std.mem.eql(u8, req.target, "/metrics")) {
                return self.apiRoute(api.metricsBody(&self.scratch, self.requests_served, self.auth_refused, self.timeouts), "text/plain");
            }
            if (req.method == .post and std.mem.eql(u8, req.target, "/v1/intents")) {
                return self.apiRoute(api.postIntent(body, &self.scratch, now_ms), "text/plain");
            }
            if (req.method == .get) {
                if (intentPathId(req.target)) |id_bytes| {
                    return self.apiRoute(api.getIntentState(id_bytes, &self.scratch), "text/plain");
                }
            }
            if (req.method == .get and std.mem.startsWith(u8, req.target, "/v1/events")) {
                const since = control_api.Api.parseSince(req.target) catch
                    return .{ .status = 400, .body = "bad request\n", .content_type = "text/plain" };
                return self.apiRoute(api.eventsSseBody(&self.scratch, since), "text/event-stream");
            }
        }
        // P2 routes land above; anything else under a valid token is 404.
        return .{ .status = 404, .body = "not found\n", .content_type = "text/plain" };
    }

    // apiRoute: copies an Api-produced outcome into a Route over the shared
    // scratch. A 404 from the API carries no body (the transport adds the
    // standard not-found text).
    fn apiRoute(self: *Control, outcome: control_api.ApiError!control_api.IntentOutcome, content_type: []const u8) Route {
        const o = outcome catch
            return .{ .status = 500, .body = "internal error\n", .content_type = "text/plain" };
        if (o.status == 404)
            return .{ .status = 404, .body = "not found\n", .content_type = "text/plain" };
        return .{ .status = o.status, .body = self.scratch[0..o.body_len], .content_type = content_type };
    }

    fn answerAndClose(self: *Control, c: *Conn, r: Route) void {
        if (r.status == 200) self.requests_served += 1;
        const head = std.fmt.bufPrint(&c.out, "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{
            r.status,
            reasonPhrase(r.status),
            r.content_type,
            r.body.len,
        }) catch {
            self.closeSlot(c);
            return;
        };
        const total = head.len + r.body.len;
        if (total > c.out.len) {
            self.closeSlot(c);
            return;
        }
        @memcpy(c.out[head.len..][0..r.body.len], r.body);
        c.out_len = total;
        c.out_sent = 0;
        // Write immediately: most responses fit one send, saving a poll lap.
        const n = libc.send(c.fd, &c.out, c.out_len, 0);
        if (n > 0) c.out_sent += @intCast(n);
        if (c.out_sent >= c.out_len) {
            self.closeSlot(c);
        } else {
            c.state = .writing;
        }
    }
};

pub const Route = struct { status: u16, body: []const u8, content_type: []const u8 };

// intentPathId: matches GET /v1/intents/{64 hex} exactly (no query, no
// trailing junk) and decodes the id; null for anything else.
fn intentPathId(target: []const u8) ?[channel.LEN_INTENT_ID]u8 {
    const prefix = "/v1/intents/";
    if (target.len != prefix.len + control_api.ID_HEX_LEN) return null;
    if (!std.mem.startsWith(u8, target, prefix)) return null;
    var hex_buf: [control_api.ID_HEX_LEN]u8 = undefined;
    @memcpy(&hex_buf, target[prefix.len..]);
    return control_api.parseIdHex(&hex_buf);
}

const forbidden_route = Route{ .status = 403, .body = "forbidden\n", .content_type = "text/plain" };

// statusRoute: the F5 table. Parser rejections map to exactly two codes:
// 400 for everything syntactic or oversized, 501 for chunked (explicit,
// never a silent drop).
fn statusRoute(e: http_parse.ParseError) Route {
    return switch (e) {
        error.ChunkedNotSupported => .{ .status = 501, .body = "chunked not supported\n", .content_type = "text/plain" },
        else => .{ .status = 400, .body = "bad request\n", .content_type = "text/plain" },
    };
}

fn reasonPhrase(status: u16) []const u8 {
    return switch (status) {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        else => "Unknown",
    };
}

fn formatStatus(buf: []u8, status: u16, body: []const u8) []const u8 {
    return std.fmt.bufPrint(buf, "HTTP/1.1 {d} {s}\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{
        status,
        reasonPhrase(status),
        body.len,
        body,
    }) catch buf[0..0];
}

fn bearerValue(auth: []const u8) ?[]const u8 {
    const pfx = "Bearer ";
    if (auth.len <= pfx.len) return null;
    if (!std.ascii.startsWithIgnoreCase(auth, pfx)) return null;
    return auth[pfx.len..];
}

// Process-static storage: same shape as daemon.zig (fixed bounds, zero heap,
// one control plane per process).
var control_storage: Control = undefined;
