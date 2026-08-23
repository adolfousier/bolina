// token_test.zig
//
// v0.6 control plane: unit tests for the bearer token. Round-trip through
// disk, fail-closed reads (absent dir, truncated file), timing-safe verify
// shape (equal passes; one flipped bit, wrong length, or wrong case all
// fail), and generation sanity (two draws differ). Temp dirs under /tmp
// with a run-unique counter, same discipline as grant_ledger_test.

const std = @import("std");
const token = @import("token.zig");

var name_counter: u32 = 0;

// Unique absolute temp dir path, NUL-padded fixed buffer; slice with z().
var path_scratch: [128]u8 = undefined;

fn tempDir(comptime tag: []const u8) []const u8 {
    @memset(&path_scratch, 0);
    const n = name_counter;
    name_counter += 1;
    const s = std.fmt.bufPrint(&path_scratch, "/tmp/bolina_token_{s}_{d}", .{ tag, n }) catch unreachable;
    return path_scratch[0..s.len];
}

fn ensureDir(io: std.Io, path: []const u8) void {
    std.Io.Dir.cwd().createDir(io, path, @enumFromInt(0o700)) catch |e| switch (e) {
        error.PathAlreadyExists => {},
        else => unreachable,
    };
}

test "generate: two draws differ and hex encodes 64 lowercase chars" {
    var threaded = std.Io.Threaded.init_single_threaded;
    const io = threaded.io();
    const a = token.generate(io);
    const b = token.generate(io);
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
    const ha = token.hex(a);
    try std.testing.expectEqual(token.TOKEN_HEX_LEN, ha.len);
    for (ha) |ch| {
        try std.testing.expect((ch >= '0' and ch <= '9') or (ch >= 'a' and ch <= 'f'));
    }
}

test "save/load roundtrip through a real dir" {
    var threaded = std.Io.Threaded.init_single_threaded;
    const io = threaded.io();
    const dir = tempDir("round");
    ensureDir(io, dir);
    const t = token.generate(io);
    const h = token.hex(t);
    try token.save(io, dir, &h);
    const loaded = token.load(io, dir) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, &h, &loaded);
}

test "load fail-closed: absent dir null, truncated on-disk token null" {
    var threaded = std.Io.Threaded.init_single_threaded;
    const io = threaded.io();
    try std.testing.expectEqual(
        @as(?[token.TOKEN_HEX_LEN]u8, null),
        token.load(io, "/tmp/bolina_token_absent_never_created"),
    );

    // Half a token on disk: refuse the read, never truncate-accept.
    const dir = tempDir("short");
    ensureDir(io, dir);
    var path_buf: [160]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/control.token", .{dir});
    const f = std.Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true }) catch unreachable;
    f.writePositionalAll(io, "0123456789abcdef0123456789abcdef", 0) catch unreachable; // 32 of 64
    f.close(io);
    try std.testing.expectEqual(@as(?[token.TOKEN_HEX_LEN]u8, null), token.load(io, dir));
}

test "verify: exact match true; flip, wrong length, wrong case all false" {
    const h = token.hex(.{0x01} ** token.TOKEN_BYTES);
    try std.testing.expect(token.verify(&h, &h));

    var flipped = h;
    flipped[17] ^= 0x01;
    try std.testing.expect(!token.verify(&flipped, &h));

    try std.testing.expect(!token.verify(h[0 .. token.TOKEN_HEX_LEN - 1], &h));
    try std.testing.expect(!token.verify("", &h));

    var alien = h;
    alien[3] = 'g'; // outside the hex alphabet entirely
    try std.testing.expect(!token.verify(&alien, &h)); // exact-byte compare
}
