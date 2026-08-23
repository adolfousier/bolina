// ca_cli_test.zig
//
// P3 tests (D-091 section 5, acceptance criterion 3): the CA CLI must produce
// material the DAEMON accepts. Each scenario runs against throwaway dirs
// under /tmp: init mints roots, issue signs a real node identity (keys.zig
// material, not test-helper keys), and the round-trip closes through
// keys.loadOrGenerate + binding.validateCert exactly as boot and binding
// consume them. Revoke bodies parse back through parser.channel.parseControl,
// the same entry the verifier's F6 site uses.

const std = @import("std");
const keys = @import("keys.zig");
const binding = @import("binding.zig");
const session = @import("parser/session.zig");
const channel = @import("parser/channel.zig");
const material = @import("ca_material.zig");
const testing = std.testing;

const IoCtx = struct {
    threaded: std.Io.Threaded,
    io: std.Io,
    fn init() IoCtx {
        return .{ .threaded = std.Io.Threaded.init_single_threaded, .io = undefined };
    }
};

var name_counter: u32 = 0;
fn tempDirPath(comptime tag: []const u8) [128]u8 {
    var buf: [128]u8 = [_]u8{0} ** 128;
    const n = name_counter;
    name_counter += 1;
    const s = std.fmt.bufPrint(&buf, "/tmp/bolina_cac_{s}_{d}", .{ tag, n }) catch unreachable;
    if (s.len < buf.len) @memset(buf[s.len..], 0);
    return buf;
}

fn cstr(buf: []const u8) []const u8 {
    var len: usize = 0;
    while (len < buf.len and buf[len] != 0) : (len += 1) {}
    return buf[0..len];
}

// Install trust anchors into a node dir's ca/ subdir: the operator flow after
// `ca init` (copy caN.pub into every node that should trust this root).
fn installTrust(io: std.Io, node_dir: []const u8, ca_dir: []const u8, count: usize) !void {
    var sub: [keys.MAX_PATH]u8 = undefined;
    const ca_sub = try std.fmt.bufPrint(&sub, "{s}/ca", .{node_dir});
    std.Io.Dir.cwd().createDir(io, ca_sub, @enumFromInt(0o700)) catch |e| switch (e) {
        error.PathAlreadyExists => {},
        else => return e,
    };
    var i: usize = 0;
    while (i < count) : (i += 1) {
        var key: [keys.KEY_LEN]u8 = undefined;
        var src: [keys.MAX_PATH]u8 = undefined;
        var dst: [keys.MAX_PATH]u8 = undefined;
        var lb: [16]u8 = undefined;
        const label = try std.fmt.bufPrint(&lb, "ca{d}.pub", .{i});
        const src_path = try std.fmt.bufPrint(&src, "{s}/ca/{s}", .{ ca_dir, label });
        const dst_path = try std.fmt.bufPrint(&dst, "{s}/{s}", .{ ca_sub, label });
        _ = try keys.readKeyFile(io, src_path, &key);
        try keys.writeKeyFile(io, dst_path, &key);
    }
}

test "P3 init writes root keys and anchors the daemon loads" {
    var ctx = IoCtx.init();
    ctx.io = ctx.threaded.io();
    var cd = tempDirPath("ca");
    defer std.Io.Dir.cwd().deleteTree(ctx.io, cstr(&cd)) catch {};
    try material.caInit(ctx.io, cstr(&cd), 2);

    // The daemon-facing layout: ca/caN.pub exist and keys.loadCas consumes them.
    var nd = tempDirPath("anchor");
    defer std.Io.Dir.cwd().deleteTree(ctx.io, cstr(&nd)) catch {};
    // Node dir exists first: loadOrGenerate creates it 0700, then anchors land
    // in {nd}/ca exactly as an operator would install them.
    _ = try keys.loadOrGenerate(ctx.io, cstr(&nd));
    try installTrust(ctx.io, cstr(&nd), cstr(&cd), 2);
    const k = try keys.loadOrGenerate(ctx.io, cstr(&nd));
    try testing.expectEqual(@as(usize, 2), k.trusted_ca_count);
}

test "P3 issue produces a cert the daemon accepts end to end" {
    var ctx = IoCtx.init();
    ctx.io = ctx.threaded.io();
    var cd = tempDirPath("ca");
    var nd = tempDirPath("node");
    defer std.Io.Dir.cwd().deleteTree(ctx.io, cstr(&cd)) catch {};
    defer std.Io.Dir.cwd().deleteTree(ctx.io, cstr(&nd)) catch {};

    try material.caInit(ctx.io, cstr(&cd), 2);
    // Node identity first: issue reads sig.pub/static.pub, never invents them.
    _ = try keys.loadOrGenerate(ctx.io, cstr(&nd));
    const res = try material.caIssue(ctx.io, .{
        .ca_dir = cstr(&cd),
        .node_dir = cstr(&nd),
        .role_bits = binding.ROLE_AGENT,
        .ttl_ms = 15 * 86_400_000,
    });

    // Daemon acceptance path: reload sees cert.bin, chain validates against
    // the loaded trust set inside the window.
    try installTrust(ctx.io, cstr(&nd), cstr(&cd), 2);
    const k = try keys.loadOrGenerate(ctx.io, cstr(&nd));
    try testing.expect(k.own_cert_len > 0);
    const cert = try session.parseCert(k.own_cert[0..k.own_cert_len]);
    try testing.expectEqualSlices(u8, &k.sig_public, cert.sig_pubkey);
    try testing.expectEqualSlices(u8, &res.serial_hex, &material.serialOf(cert.tbs));
    const trusted = [_][]const u8{ &k.trusted_ca_keys[0], &k.trusted_ca_keys[1] };
    try binding.validateCert(cert, &trusted, cert.not_before + 1_000);
}

test "P3 tampered tbs dies at the CA signature check" {
    var ctx = IoCtx.init();
    ctx.io = ctx.threaded.io();
    var cd = tempDirPath("ca");
    var nd = tempDirPath("node");
    defer std.Io.Dir.cwd().deleteTree(ctx.io, cstr(&cd)) catch {};
    defer std.Io.Dir.cwd().deleteTree(ctx.io, cstr(&nd)) catch {};

    try material.caInit(ctx.io, cstr(&cd), 1);
    _ = try keys.loadOrGenerate(ctx.io, cstr(&nd));
    _ = try material.caIssue(ctx.io, .{
        .ca_dir = cstr(&cd),
        .node_dir = cstr(&nd),
        .role_bits = binding.ROLE_AGENT,
        .ttl_ms = 86_400_000,
    });
    try installTrust(ctx.io, cstr(&nd), cstr(&cd), 1);
    var k = try keys.loadOrGenerate(ctx.io, cstr(&nd));
    k.own_cert[4] ^= 0x01; // flip one role/window byte under the signature
    const cert = try session.parseCert(k.own_cert[0..k.own_cert_len]);
    const trusted = [_][]const u8{&k.trusted_ca_keys[0]};
    try testing.expectError(error.BadCASignature, binding.validateCertNoClock(cert, &trusted));
}

test "P3 approver issuance enforces quorum and span cap" {
    var ctx = IoCtx.init();
    ctx.io = ctx.threaded.io();
    var cd1 = tempDirPath("ca");
    var cd2 = tempDirPath("ca");
    var nd = tempDirPath("node");
    defer std.Io.Dir.cwd().deleteTree(ctx.io, cstr(&cd1)) catch {};
    defer std.Io.Dir.cwd().deleteTree(ctx.io, cstr(&cd2)) catch {};
    defer std.Io.Dir.cwd().deleteTree(ctx.io, cstr(&nd)) catch {};

    // One root only: an approver cert cannot meet quorum 2 at receipt.
    try material.caInit(ctx.io, cstr(&cd1), 1);
    _ = try keys.loadOrGenerate(ctx.io, cstr(&nd));
    try installTrust(ctx.io, cstr(&nd), cstr(&cd1), 1);
    _ = try material.caIssue(ctx.io, .{
        .ca_dir = cstr(&cd1),
        .node_dir = cstr(&nd),
        .role_bits = binding.ROLE_APPROVER,
        .ttl_ms = 86_400_000,
    });
    var k = try keys.loadOrGenerate(ctx.io, cstr(&nd));
    const cert1 = try session.parseCert(k.own_cert[0..k.own_cert_len]);
    const trusted1 = [_][]const u8{&k.trusted_ca_keys[0]};
    try testing.expectError(error.ApproverNoQuorum, binding.validateCertNoClock(cert1, &trusted1));

    // Two roots but a 31-day span: refused at the SOURCE (TtlOverCap), so no
    // over-cap privileged cert can ever exist to be rejected downstream.
    try material.caInit(ctx.io, cstr(&cd2), 2);
    try testing.expectError(error.TtlOverCap, material.caIssue(ctx.io, .{
        .ca_dir = cstr(&cd2),
        .node_dir = cstr(&nd),
        .role_bits = binding.ROLE_APPROVER,
        .ttl_ms = 31 * 86_400_000,
    }));
    // Quorum met with two roots and a legal span validates clean. The cd2
    // anchors overwrite cd1's slots by filename, mirroring a root rotation.
    try installTrust(ctx.io, cstr(&nd), cstr(&cd2), 2);
    _ = try material.caIssue(ctx.io, .{
        .ca_dir = cstr(&cd2),
        .node_dir = cstr(&nd),
        .role_bits = binding.ROLE_APPROVER,
        .ttl_ms = 30 * 86_400_000,
    });
    k = try keys.loadOrGenerate(ctx.io, cstr(&nd));
    const cert2 = try session.parseCert(k.own_cert[0..k.own_cert_len]);
    const trusted2 = [_][]const u8{ &k.trusted_ca_keys[0], &k.trusted_ca_keys[1] };
    try binding.validateCertNoClock(cert2, &trusted2);
}

test "P3 revoke emits a BE-CTRL-03 body the verifier site parses" {
    var ctx = IoCtx.init();
    ctx.io = ctx.threaded.io();
    var cd = tempDirPath("ca");
    var nd = tempDirPath("node");
    var od = tempDirPath("rev");
    defer std.Io.Dir.cwd().deleteTree(ctx.io, cstr(&cd)) catch {};
    defer std.Io.Dir.cwd().deleteTree(ctx.io, cstr(&nd)) catch {};
    defer std.Io.Dir.cwd().deleteTree(ctx.io, cstr(&od)) catch {};

    try material.caInit(ctx.io, cstr(&cd), 1);
    _ = try keys.loadOrGenerate(ctx.io, cstr(&nd));
    std.Io.Dir.cwd().createDir(ctx.io, cstr(&od), @enumFromInt(0o700)) catch |e| switch (e) {
        error.PathAlreadyExists => {},
        else => return e,
    };
    const res = try material.caIssue(ctx.io, .{
        .ca_dir = cstr(&cd),
        .node_dir = cstr(&nd),
        .role_bits = binding.ROLE_AGENT,
        .ttl_ms = 86_400_000,
    });
    const k = try keys.loadOrGenerate(ctx.io, cstr(&nd));

    // Default expiry: the subject cert's own not_after (D-090 pruning value).
    var out_default: [256]u8 = [_]u8{0} ** 256;
    const out_a = try std.fmt.bufPrint(&out_default, "{s}/revoke-default.bin", .{cstr(&od)});
    try material.caRevoke(ctx.io, cstr(&cd), &res.serial_hex, null, out_a);
    var raw: [44]u8 = undefined; // exact Control body size: ver|action|subject|len|u64be
    {
        const f = try std.Io.Dir.cwd().openFile(ctx.io, out_a, .{});
        defer f.close(ctx.io);
        const n = try f.readPositionalAll(ctx.io, &raw, 0);
        try testing.expectEqual(@as(usize, 44), n);
        const control = try channel.parseControl(raw[0..n]);
        try testing.expectEqual(@as(u8, 2), control.action_type);
        try testing.expectEqualSlices(u8, &k.sig_public, control.subject);
        try testing.expectEqual(@as(usize, 8), control.body.len);
        const expiry = std.mem.readInt(u64, control.body[0..8], .big);
        const cert = try session.parseCert(k.own_cert[0..k.own_cert_len]);
        try testing.expectEqual(cert.not_after, expiry);
    }

    // Explicit expiry rides through; unknown serials are refused, not guessed.
    var out_explicit: [256]u8 = [_]u8{0} ** 256;
    const out_b = try std.fmt.bufPrint(&out_explicit, "{s}/revoke-explicit.bin", .{cstr(&od)});
    try material.caRevoke(ctx.io, cstr(&cd), &res.serial_hex, 123_456, out_b);
    {
        const f = try std.Io.Dir.cwd().openFile(ctx.io, out_b, .{});
        defer f.close(ctx.io);
        const n = try f.readPositionalAll(ctx.io, &raw, 0);
        const control = try channel.parseControl(raw[0..n]);
        try testing.expectEqual(@as(u64, 123_456), std.mem.readInt(u64, control.body[0..8], .big));
    }
    var bad_serial: [32]u8 = res.serial_hex;
    bad_serial[0] = 'f';
    bad_serial[1] = if (res.serial_hex[1] == 'f') '0' else res.serial_hex[1];
    var out_c: [256]u8 = [_]u8{0} ** 256;
    const out_d = try std.fmt.bufPrint(&out_c, "{s}/revoke-bad.bin", .{cstr(&od)});
    try testing.expectError(error.CertUnreadable, material.caRevoke(ctx.io, cstr(&cd), &bad_serial, null, out_d));
}
