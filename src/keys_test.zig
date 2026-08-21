// keys_test.zig
//
// Unit tests for node key material (D-018, D-089 section 1). Each test runs
// against its own throwaway data dir under /tmp: generate, reload, and the
// distinct fatal paths (tampered public, truncated secret, cert passthrough,
// CA subdir loading) each get one focused scenario.

const std = @import("std");
const keys = @import("keys.zig");
const testing = std.testing;

// Same threaded-io pairing as grant_ledger_test: the threaded value outlives
// the io borrow, both live on the test stack.
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
    const s = std.fmt.bufPrint(&buf, "/tmp/bolina_keys_{s}_{d}", .{ tag, n }) catch unreachable;
    if (s.len < buf.len) @memset(buf[s.len..], 0);
    return buf;
}

fn cstr(buf: []const u8) []const u8 {
    var len: usize = 0;
    while (len < buf.len and buf[len] != 0) : (len += 1) {}
    return buf[0..len];
}

// Remove every file keys.zig can create, then the ca/ subdir, then the data
// dir itself. Missing entries are ignored: cleanup must never mask a failure.
fn cleanupDir(io: std.Io, path: []const u8) void {
    const dir = std.Io.Dir.cwd();
    const root_names = [_][]const u8{ "static.key", "static.pub", "sig.key", "sig.pub", "cert.bin" };
    for (root_names) |nm| {
        var pb: [keys.MAX_PATH]u8 = undefined;
        const p = std.fmt.bufPrint(&pb, "{s}/{s}", .{ path, nm }) catch return;
        dir.deleteFile(io, p) catch {};
    }
    var ca_buf: [keys.MAX_PATH]u8 = undefined;
    const ca_path = std.fmt.bufPrint(&ca_buf, "{s}/ca", .{path}) catch return;
    var i: usize = 0;
    while (i < keys.MAX_CAS) : (i += 1) {
        var lb: [8]u8 = undefined;
        const label = std.fmt.bufPrint(&lb, "ca{d}.pub", .{i}) catch return;
        var pb: [keys.MAX_PATH]u8 = undefined;
        const p = std.fmt.bufPrint(&pb, "{s}/{s}", .{ ca_path, label }) catch return;
        dir.deleteFile(io, p) catch {};
    }
    dir.deleteDir(io, ca_path) catch {};
    dir.deleteDir(io, path) catch {};
}

fn rawWrite(io: std.Io, path: []const u8, bytes: []const u8) !void {
    const dir = std.Io.Dir.cwd();
    const f = try dir.createFile(io, path, .{ .read = true, .truncate = true });
    defer f.close(io);
    try f.writePositionalAll(io, bytes, 0);
}

test "keys: first run generates, second run reloads identical material (D-018)" {
    var ctx = IoCtx.init();
    ctx.io = ctx.threaded.io();
    const io = ctx.io;
    const path_buf = tempDirPath("gen");
    const path = cstr(&path_buf);
    defer cleanupDir(io, path);

    const first = try keys.loadOrGenerate(io, path);
    // Fresh dir: no cert, no CAs -> unbound-accept shape.
    try testing.expectEqual(@as(usize, 0), first.own_cert_len);
    try testing.expectEqual(@as(usize, 0), first.trusted_ca_count);
    // Nothing is zeroed key material (D-018): all four 32B values nonzero.
    var any_zero = true;
    for (first.kex_secret) |b| any_zero = any_zero and (b == 0);
    try testing.expect(!any_zero);
    any_zero = true;
    for (first.sig_public) |b| any_zero = any_zero and (b == 0);
    try testing.expect(!any_zero);

    const second = try keys.loadOrGenerate(io, path);
    try testing.expectEqualSlices(u8, &first.kex_secret, &second.kex_secret);
    try testing.expectEqualSlices(u8, &first.kex_public, &second.kex_public);
    try testing.expectEqualSlices(u8, &first.sig_seed, &second.sig_seed);
    try testing.expectEqualSlices(u8, &first.sig_public, &second.sig_public);
}

test "keys: tampered static.pub is a distinct fatal, never silently accepted" {
    var ctx = IoCtx.init();
    ctx.io = ctx.threaded.io();
    const io = ctx.io;
    const path_buf = tempDirPath("tamper");
    const path = cstr(&path_buf);
    defer cleanupDir(io, path);

    _ = try keys.loadOrGenerate(io, path);
    // Overwrite the stored public with a different (well-formed) 32B key.
    var bogus: [keys.KEY_LEN]u8 = undefined;
    @memset(&bogus, 0xAB);
    var pb: [keys.MAX_PATH]u8 = undefined;
    const pub_path = std.fmt.bufPrint(&pb, "{s}/static.pub", .{path}) catch unreachable;
    try rawWrite(io, pub_path, &bogus);
    try testing.expectError(error.PubMismatch, keys.loadOrGenerate(io, path));
}

test "keys: truncated secret file is corruption, not regeneration" {
    var ctx = IoCtx.init();
    ctx.io = ctx.threaded.io();
    const io = ctx.io;
    const path_buf = tempDirPath("short");
    const path = cstr(&path_buf);
    defer cleanupDir(io, path);

    _ = try keys.loadOrGenerate(io, path);
    // Shrink sig.key to 16 bytes: length is corruption, files are raw fixed keys.
    var half: [16]u8 = undefined;
    @memset(&half, 0x5A);
    var pb: [keys.MAX_PATH]u8 = undefined;
    const sig_path = std.fmt.bufPrint(&pb, "{s}/sig.key", .{path}) catch unreachable;
    try rawWrite(io, sig_path, &half);
    try testing.expectError(error.KeyFileCorrupt, keys.loadOrGenerate(io, path));
}

test "keys: cert.bin loads verbatim; absent stays unbound-accept" {
    var ctx = IoCtx.init();
    ctx.io = ctx.threaded.io();
    const io = ctx.io;
    const path_buf = tempDirPath("cert");
    const path = cstr(&path_buf);
    defer cleanupDir(io, path);

    _ = try keys.loadOrGenerate(io, path);
    var cert: [200]u8 = undefined;
    for (&cert, 0..) |*b, i| b.* = @intCast(i % 251);
    var pb: [keys.MAX_PATH]u8 = undefined;
    const cert_path = std.fmt.bufPrint(&pb, "{s}/cert.bin", .{path}) catch unreachable;
    try rawWrite(io, cert_path, &cert);

    const reloaded = try keys.loadOrGenerate(io, path);
    try testing.expectEqual(@as(usize, 200), reloaded.own_cert_len);
    try testing.expectEqualSlices(u8, cert[0..], reloaded.own_cert[0..reloaded.own_cert_len]);
}

test "keys: CA keys load from the ca/ subdir in label order" {
    var ctx = IoCtx.init();
    ctx.io = ctx.threaded.io();
    const io = ctx.io;
    const path_buf = tempDirPath("cas");
    const path = cstr(&path_buf);
    defer cleanupDir(io, path);

    _ = try keys.loadOrGenerate(io, path);
    const dir = std.Io.Dir.cwd();
    var ca_buf: [keys.MAX_PATH]u8 = undefined;
    const ca_path = std.fmt.bufPrint(&ca_buf, "{s}/ca", .{path}) catch unreachable;
    try dir.createDir(io, ca_path, @enumFromInt(0o755));
    var first_key: [keys.KEY_LEN]u8 = undefined;
    @memset(&first_key, 0x11);
    var second_key: [keys.KEY_LEN]u8 = undefined;
    @memset(&second_key, 0x22);
    var pb0: [keys.MAX_PATH]u8 = undefined;
    const p0 = std.fmt.bufPrint(&pb0, "{s}/ca0.pub", .{ca_path}) catch unreachable;
    try rawWrite(io, p0, &first_key);
    var pb1: [keys.MAX_PATH]u8 = undefined;
    const p1 = std.fmt.bufPrint(&pb1, "{s}/ca1.pub", .{ca_path}) catch unreachable;
    try rawWrite(io, p1, &second_key);

    const reloaded = try keys.loadOrGenerate(io, path);
    try testing.expectEqual(@as(usize, 2), reloaded.trusted_ca_count);
    try testing.expectEqualSlices(u8, &first_key, &reloaded.trusted_ca_keys[0]);
    try testing.expectEqualSlices(u8, &second_key, &reloaded.trusted_ca_keys[1]);
}

test "keys: fingerprint is stable lowercase hex over the public prefix" {
    var pub_bytes: [keys.KEY_LEN]u8 = undefined;
    @memset(&pub_bytes, 0x0F);
    const a = keys.fingerprint(&pub_bytes);
    const b = keys.fingerprint(&pub_bytes);
    try testing.expectEqualSlices(u8, &a, &b);
    for (a) |c| try testing.expect(std.ascii.isHex(c) and !std.ascii.isUpper(c));
    // Different key, different fingerprint.
    pub_bytes[0] = 0x10;
    const c = keys.fingerprint(&pub_bytes);
    try testing.expect(!std.mem.eql(u8, &a, &c));
}
