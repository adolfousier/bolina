// main.zig
//
// Bolina daemon entry point. D-089 section 3: fail-fast boot in a fixed
// order, then the recv loop. Every decision about bytes lives in daemon.zig;
// this file parses env, loads material, opens the ledger, claims the port,
// and turns the crank.
//
// Config surface (env only, D-089 section 2: no config file, no other knobs):
//   BOLINA_BIND     - UDP bind, "a.b.c.d:port" (default "0.0.0.0:7420")
//   BOLINA_DATA_DIR - key material home, created 0700 (default "~/.bolina")
//   BOLINA_LEDGER   - grant ledger path (default "$BOLINA_DATA_DIR/ledger.bin")
//   BOLINA_TEST_CA  - dev-only; always fatal in this binary (pilots mint
//                     their CA in-process, never through env)
//
// D-018: keys are load-or-generate from BOLINA_DATA_DIR (0600 files, 0700
// dir); nothing here is hardcoded or zeroed. Logs carry fingerprints only.

const std = @import("std");
const listener = @import("listener.zig");
const handshake = @import("handshake.zig");
const noise = @import("noise.zig");
const keys_mod = @import("keys.zig");
const daemon_mod = @import("daemon.zig");
const dispatch_mod = @import("dispatch.zig");
const grant_ledger = @import("grant_ledger.zig");
const control_mod = @import("control.zig");
const control_api = @import("control_api.zig");
const token_mod = @import("token.zig");
const ca_cli = @import("ca_cli.zig");

const MAX_DGRAM: usize = 2048;
const SA_LEN: usize = 28;

// Flat libc seam, same house pattern as listener.zig/handshake.zig: Zig 0.16
// keeps env and clocks behind std.Io/posix surfaces that do not fit a flat
// daemon loop, so main talks to libc directly like every other wire module.
extern "c" fn getenv(name: [*:0]const u8) ?[*:0]u8;
extern "c" fn clock_gettime(clk_id: c_int, tp: *Timespec) c_int;
extern "c" fn signal(sig: c_int, handler: ?*const fn (c_int) callconv(.c) void) ?*const fn (c_int) callconv(.c) void;

// SIGTERM/SIGINT land here: flip the flag, nothing else (async-signal-safe).
// The control-plane runLoop polls it between laps; without BOLINA_CONTROL
// there is no graceful stop and the plain recv loop runs until killed.
var shutdown_flag = std.atomic.Value(bool).init(false);
const SIGINT: c_int = 2;
const SIGTERM: c_int = 15;
fn onRequestStop(_: c_int) callconv(.c) void {
    shutdown_flag.store(true, .monotonic);
}

// CLOCK_REALTIME is 0 on Linux and macOS both. The daemon's clock is wall
// time on purpose: cert validity windows (BE-ID-02) are absolute times, and
// the sequence-window consumers (replay filter) run on counters, not clocks.
const CLOCK_REALTIME: c_int = 0;
const Timespec = extern struct { sec: c_long, nsec: c_long };

fn wallMs() u64 {
    var ts: Timespec = undefined;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) return 0;
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(@divTrunc(ts.nsec, 1_000_000)));
}

fn envOr(comptime name: [:0]const u8) ?[:0]const u8 {
    const p = getenv(name) orelse return null;
    return std.mem.span(p);
}

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("bolina: fatal: " ++ fmt ++ "\n", args);
    std.process.exit(1);
}

fn hexBytes(out: []u8, bytes: []const u8) []const u8 {
    const digits = "0123456789abcdef";
    var i: usize = 0;
    while (i < bytes.len and (i * 2 + 1) < out.len) : (i += 1) {
        out[i * 2] = digits[bytes[i] >> 4];
        out[i * 2 + 1] = digits[bytes[i] & 0xf];
    }
    return out[0 .. i * 2];
}

// parseBind: "a.b.c.d:port" into the raw 4-byte address listener.bind wants.
fn parseBind(spec: []const u8) ?struct { bytes: [4]u8, port: u16 } {
    const colon = std.mem.lastIndexOfScalar(u8, spec, ':') orelse return null;
    var bytes: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, spec[0..colon], '.');
    var i: usize = 0;
    while (it.next()) |part| : (i += 1) {
        if (i >= 4 or part.len == 0) return null;
        bytes[i] = std.fmt.parseInt(u8, part, 10) catch return null;
    }
    if (i != 4) return null;
    const port = std.fmt.parseInt(u16, spec[colon + 1 ..], 10) catch return null;
    return .{ .bytes = bytes, .port = port };
}

// resolvePath: expand a leading "~" against $HOME, copy into out, return the
// slice of out. No allocator: boot-time strings live in fixed buffers.
fn resolvePath(spec: []const u8, out: []u8) []const u8 {
    if (!std.mem.startsWith(u8, spec, "~")) {
        if (spec.len > out.len) fatal("path too long: {s}", .{spec});
        @memcpy(out[0..spec.len], spec);
        return out[0..spec.len];
    }
    const home = envOr("HOME") orelse fatal("~ in path but HOME is unset", .{});
    const rest = spec[1..]; // keep the "/" if present
    const total = home.len + rest.len;
    if (total > out.len) fatal("path too long: {s}", .{spec});
    @memcpy(out[0..home.len], home);
    @memcpy(out[home.len..total], rest);
    return out[0..total];
}

pub fn main(init: std.process.Init) !void {
    var threaded_io = std.Io.Threaded.init_single_threaded;
    const io = threaded_io.io();

    // 0. Offline CA subcommands (D-091 section 5) exit before any daemon state
    // exists: `bolina ca init|issue|revoke|list|show` mint and inspect
    // material; the daemon below is the only network citizen. Argv collected
    // once into a fixed stack table: zero heap on the daemon path.
    var argv: [24][:0]const u8 = undefined;
    var argv_n: usize = 0;
    {
        var ait = std.process.Args.Iterator.init(init.minimal.args);
        while (ait.next()) |a| {
            if (argv_n == argv.len) break;
            argv[argv_n] = a;
            argv_n += 1;
        }
    }
    if (try ca_cli.maybeRun(io, argv[0..argv_n])) return;

    // 1. Env. Unparseable or dev-only values exit before anything mutates.
    if (envOr("BOLINA_TEST_CA") != null)
        fatal("BOLINA_TEST_CA is dev-only; test pilots mint their CA in-process", .{});
    const bind_spec_default = "0.0.0.0:7420";
    const bind_spec = envOr("BOLINA_BIND") orelse bind_spec_default;
    const bind = parseBind(bind_spec) orelse fatal("unparseable BOLINA_BIND '{s}' (want a.b.c.d:port)", .{bind_spec});

    // 2-3. Data dir + keys. loadOrGenerate creates the dir 0700 and each file
    // 0600 on first run; a PubMismatch tamper exits here, loudly (D-018).
    var dir_buf: [512]u8 = undefined;
    var led_buf: [512]u8 = undefined;
    const data_dir = resolvePath(envOr("BOLINA_DATA_DIR") orelse "~/.bolina", &dir_buf);
    const keys_val = keys_mod.loadOrGenerate(io, data_dir) catch |e|
        fatal("key material under {s}: {s}", .{ data_dir, @errorName(e) });
    // fingerprint() already returns rendered hex (16 ASCII chars); printing
    // it through hexBytes double-encoded the identity and made operators
    // quote a fp no resolver would ever accept (found live in the P2 smoke:
    // BOLINA_RESOURCES with the printed fp died ForeignExecutor).
    std.debug.print("bolina: identity fingerprint {s}\n", .{keys_mod.fingerprint(&keys_val.sig_public)});
    std.debug.print("bolina: kex fingerprint {s} ({d} trusted CAs, {s})\n", .{
        keys_mod.fingerprint(&keys_val.kex_public),
        keys_val.trusted_ca_count,
        if (keys_val.own_cert_len > 0) "cert loaded" else "no cert: unbound-accept mode",
    });

    // 4. Ledger. A corrupt log is fatal at boot, never truncated in place;
    // recovered orphans are logged and tombstoned (their interrupted-effect
    // publication lands with the effect backend, D-089).
    const ledger_path = if (envOr("BOLINA_LEDGER")) |p| resolvePath(p, &led_buf) else blk: {
        break :blk std.fmt.bufPrint(&led_buf, "{s}/ledger.bin", .{data_dir}) catch fatal("paths too long", .{});
    };
    var orphans: [daemon_mod.MAX_ORPHANS_BOOT]grant_ledger.OrphanGrant = undefined;
    const n_orphans = daemon_mod.openLedger(io, ledger_path, &orphans) catch |e| switch (e) {
        error.OrphanOverflow => fatal("ledger at {s}: more recovered orphans than the boot bound {d}", .{ ledger_path, orphans.len }),
        else => fatal("ledger at {s}: open/recover refused ({s}); corrupt logs are fatal by design", .{ ledger_path, @errorName(e) }),
    };
    for (orphans[0..n_orphans]) |og| {
        var id_hex: [65]u8 = undefined;
        std.debug.print("bolina: orphan grant committed-but-unpublished, tombstoning: {s}\n", .{hexBytes(&id_hex, &og.grant_id)});
        dispatch_mod.tombstoneOrphan(og.grant_id) catch {};
    }

    // 7-8. Handshake server + listener. EADDRINUSE (BindRefused) is fatal:
    // single-instance pairs with MD3's single-writer ledger lock.
    var lis = listener.Listener.open(.ipv4) catch |e|
        fatal("listener socket: {s}", .{@errorName(e)});
    var registry = listener.EndpointRegistry{};
    lis.bind(&registry, &bind.bytes, bind.port) catch |e|
        fatal("bind {s}:{d} refused ({s}); another node may hold the endpoint", .{ bind_spec, bind.port, @errorName(e) });

    var hs = handshake.HandshakeServer{
        .fd = lis.fd,
        .responder_static = noise.X25519KeyPair{ .secret = keys_val.kex_secret, .public = keys_val.kex_public },
        .responder_sig_pubkey = keys_val.sig_public,
        .io = io,
    };

    // 5-6. Intent table (fresh; BE-GRANT-04 restart collapse is by design)
    // and dispatch init inside the daemon.
    const d = daemon_mod.Daemon.init(io, &lis, &keys_val, &hs, null) catch |e|
        fatal("daemon init: {s}", .{@errorName(e)});

    std.debug.print("bolina: node up on {s}, ledger {s}, entering recv loop\n", .{ bind_spec, ledger_path });

    // Declared resources (D-091): the executor serves ONLY what it declares
    // (BE-RES-02 unknown-refuse), so without BOLINA_RESOURCES the node admits
    // nothing over wire or HTTP alike, which is exactly fail-closed.
    // Comma-separated canonical ids ("bol:<fp>/<ns>/<name>"); a malformed or
    // duplicate entry is fatal at boot rather than a silent admission gap.
    if (envOr("BOLINA_RESOURCES")) |res_list| {
        var res_it = std.mem.splitScalar(u8, res_list, ',');
        while (res_it.next()) |raw| {
            const name = std.mem.trim(u8, raw, " ");
            if (name.len == 0) continue;
            d.dispatcher.resolver.add(name) catch |e|
                fatal("resource '{s}' refused by resolver: {s}", .{ name, @errorName(e) });
        }
    }

    // Control plane (D-091): opt-in via BOLINA_CONTROL ("a.b.c.d:port",
    // default 127.0.0.1:7421). The bearer token is load-or-generate under
    // the data dir; the print-once contract means the hex appears in boot
    // output exactly when it is minted, never again. Without the env the
    // plain recv loop below runs byte-for-byte as before (pilot e2e proof).
    if (envOr("BOLINA_CONTROL")) |ctl_spec| {
        const ctl_default = "127.0.0.1:7421";
        const spec = if (ctl_spec.len == 0) ctl_default else ctl_spec;
        const cbind = parseBind(spec) orelse fatal("unparseable BOLINA_CONTROL '{s}' (want a.b.c.d:port)", .{spec});
        var token_hex: [token_mod.TOKEN_HEX_LEN]u8 = undefined;
        if (token_mod.load(io, data_dir)) |t| {
            token_hex = t;
        } else {
            token_hex = token_mod.hex(token_mod.generate(io));
            token_mod.save(io, data_dir, &token_hex) catch |e|
                fatal("control token save under {s}: {s}", .{ data_dir, @errorName(e) });
            std.debug.print("bolina: control plane token {s} (printed once; stored at {s}/control.token)\n", .{ token_hex, data_dir });
        }
        const ctl_node = control_mod.Control.init(&cbind.bytes, cbind.port, &token_hex) catch |e|
            fatal("control plane bind {s} refused ({s})", .{ spec, @errorName(e) });
        // Attach the /v1 facade to the daemon's own dispatch machines (D-091
        // zero-god-mode): the Api holds pointers into the static Daemon, so
        // HTTP intents land in the SAME table/resolver the wire path uses,
        // and grant events flow out through the same ring dispatch publishes.
        var ring = control_api.EventRing{};
        dispatch_mod.attachEvents(&ring);
        var api = control_api.Api{
            .resolver = &d.dispatcher.resolver,
            .table = &d.dispatcher.intents,
            .ring = &ring,
        };
        ctl_node.api = &api;
        _ = signal(SIGTERM, onRequestStop);
        _ = signal(SIGINT, onRequestStop);
        std.debug.print("bolina: control plane on {s}\n", .{spec});
        ctl_node.runLoop(d, lis.fd, &shutdown_flag, wallMs);
        std.debug.print("bolina: shutdown complete, ledger consistent\n", .{});
        return;
    }

    // 9. Recv loop. One thread, one buffer, one classification per datagram;
    // handleDatagram drops what it cannot serve and counts it.
    var buf: [MAX_DGRAM]u8 = undefined;
    var sa: [SA_LEN]u8 = undefined;
    var sa_len: c_uint = SA_LEN;
    while (true) {
        const n = lis.recvFrom(&buf, &sa, &sa_len) catch continue;
        if (n == 0) continue;
        _ = d.handleDatagram(buf[0..n], &sa, sa_len, wallMs());
        sa_len = SA_LEN;
    }
}
