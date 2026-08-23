// token.zig
//
// v0.6 control plane auth (D-091 section 3, F7 ruling): one bearer token,
// generated from io.random at first boot, stored 0600 next to the key
// material, compared timing-safely. The control plane is loopback-only;
// the token exists so another process of the same user (or a drive-by
// page against localhost) cannot drive intents or read events.
//
// Fail-closed posture: an absent, short, or unreadable token file refuses
// every request except /healthz - the caller treats load() == null as
// "auth impossible", never as "auth skipped". Regeneration happens only
// through an explicit operator delete, never silently at boot: a restart
// must not rotate credentials under running clients.

const std = @import("std");

pub const TOKEN_BYTES: usize = 32;
pub const TOKEN_HEX_LEN: usize = 64; // 2 chars per byte
const FILE_NAME = "control.token";
const MAX_PATH: usize = 256;

pub const TokenError = error{DiskError};

// generate: 32 fresh bytes from the Io CSPRNG (same entropy source the
// key material uses, keys.zig generate(io)).
pub fn generate(io: std.Io) [TOKEN_BYTES]u8 {
    var raw: [TOKEN_BYTES]u8 = undefined;
    io.random(&raw);
    return raw;
}

// hex: lowercase fixed-width encoding; the on-disk and header form.
pub fn hex(token: [TOKEN_BYTES]u8) [TOKEN_HEX_LEN]u8 {
    var out: [TOKEN_HEX_LEN]u8 = undefined;
    const digits = "0123456789abcdef";
    for (token, 0..) |b, i| {
        out[i * 2] = digits[b >> 4];
        out[i * 2 + 1] = digits[b & 0xf];
    }
    return out;
}

// save: write the hex form 0600. Overwrite is allowed (rotation is a
// deliberate operator step), creation is not exclusive by design.
pub fn save(io: std.Io, data_dir: []const u8, token_hex: *const [TOKEN_HEX_LEN]u8) TokenError!void {
    var buf: [MAX_PATH + FILE_NAME.len]u8 = undefined;
    const path = std.fmt.bufPrint(&buf, "{s}/" ++ FILE_NAME, .{data_dir}) catch return error.DiskError;
    const dir = std.Io.Dir.cwd();
    const f = dir.createFile(io, path, .{ .read = true, .truncate = true, .permissions = @enumFromInt(0o600) }) catch return error.DiskError;
    defer f.close(io);
    f.writePositionalAll(io, token_hex, 0) catch return error.DiskError;
}

// load: null on any absence/short-read/corruption. The caller fails
// closed on null; this layer never invents a fallback token.
pub fn load(io: std.Io, data_dir: []const u8) ?[TOKEN_HEX_LEN]u8 {
    var buf: [MAX_PATH + FILE_NAME.len]u8 = undefined;
    const path = std.fmt.bufPrint(&buf, "{s}/" ++ FILE_NAME, .{data_dir}) catch return null;
    const dir = std.Io.Dir.cwd();
    const f = dir.openFile(io, path, .{}) catch return null;
    defer f.close(io);
    var out: [TOKEN_HEX_LEN]u8 = undefined;
    const n = f.readPositionalAll(io, &out, 0) catch return null;
    if (n != TOKEN_HEX_LEN) return null;
    return out;
}

// verify: constant-time over the fixed-length hex. A length mismatch
// exits before the compare (length leaks; content never does). The
// provided copy lands in a stack buffer first because timing_safe.eql
// wants equal-length arrays and slicing attacker input directly into it
// would be a branch anyway.
pub fn verify(provided: []const u8, expected: *const [TOKEN_HEX_LEN]u8) bool {
    if (provided.len != TOKEN_HEX_LEN) return false;
    var p: [TOKEN_HEX_LEN]u8 = undefined;
    @memcpy(&p, provided);
    return std.crypto.timing_safe.eql([TOKEN_HEX_LEN]u8, p, expected.*);
}
