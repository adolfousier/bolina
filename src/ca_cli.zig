// ca_cli.zig
//
// Argv shell over ca_material (D-091 section 5):
//   bolina ca init   --dir D [--count N]
//   bolina ca issue  --ca-dir D --node-dir N --role agent|executor|approver
//                    [--ttl 15d|h|m] [--name s] [--scope hex8]...
//   bolina ca revoke --ca-dir D --serial H [--subject-expiry-ms T] --out F
//   bolina ca list   --ca-dir D
//   bolina ca show   --ca-dir D --serial H
// main dispatches here before any daemon state exists; all material work
// happens in ca_material.zig, offline, touching no network.

const std = @import("std");
const material = @import("ca_material.zig");
const session = @import("parser/session.zig");
const keys_mod = @import("keys.zig");

const MAX_PATH: usize = 512;
pub const MAX_SERIALS_LIST: usize = 128;

pub const CliError = error{
    UnknownCommand,
    MissingFlagValue,
    BadTtl,
    BadScopeHex,
    ScopeOverrun,
    SerialNotFound,
};

const Flags = struct {
    dir: ?[]const u8 = null,
    ca_dir: ?[]const u8 = null,
    node_dir: ?[]const u8 = null,
    role: ?[]const u8 = null,
    ttl: ?[]const u8 = null,
    name: ?[]const u8 = null,
    serial: ?[]const u8 = null,
    out: ?[]const u8 = null,
    count: usize = 2, // default 2 roots: approver quorum is 2 (BE-ID-04)
    subject_expiry_ms: ?u64 = null,
    scopes: [8][8]u8 = undefined,
    scope_count: usize = 0,

    fn set(self: *Flags, flag: []const u8, val: []const u8) CliError!void {
        if (std.mem.eql(u8, flag, "--dir")) {
            self.dir = val;
        } else if (std.mem.eql(u8, flag, "--ca-dir")) {
            self.ca_dir = val;
        } else if (std.mem.eql(u8, flag, "--node-dir")) {
            self.node_dir = val;
        } else if (std.mem.eql(u8, flag, "--role")) {
            self.role = val;
        } else if (std.mem.eql(u8, flag, "--ttl")) {
            self.ttl = val;
        } else if (std.mem.eql(u8, flag, "--name")) {
            self.name = val;
        } else if (std.mem.eql(u8, flag, "--serial")) {
            self.serial = val;
        } else if (std.mem.eql(u8, flag, "--out")) {
            self.out = val;
        } else if (std.mem.eql(u8, flag, "--count")) {
            self.count = std.fmt.parseInt(usize, val, 10) catch return error.BadTtl;
        } else if (std.mem.eql(u8, flag, "--subject-expiry-ms")) {
            self.subject_expiry_ms = std.fmt.parseInt(u64, val, 10) catch return error.BadTtl;
        } else if (std.mem.eql(u8, flag, "--scope")) {
            if (self.scope_count >= self.scopes.len) return error.ScopeOverrun;
            _ = std.fmt.hexToBytes(&self.scopes[self.scope_count], val) catch return error.BadScopeHex;
            self.scope_count += 1;
        } else return error.UnknownCommand;
    }
};

fn parseTtl(s: []const u8) CliError!u64 {
    if (s.len < 2) return error.BadTtl;
    const unit: u64 = switch (s[s.len - 1]) {
        'd' => 86_400_000,
        'h' => 3_600_000,
        'm' => 60_000,
        else => return error.BadTtl,
    };
    const n = std.fmt.parseInt(u64, s[0 .. s.len - 1], 10) catch return error.BadTtl;
    if (n == 0 or n > 3650) return error.BadTtl;
    return unit * n;
}

fn require(val: ?[]const u8) CliError![]const u8 {
    return val orelse error.MissingFlagValue;
}

/// argv comes from main's std.process.Init iterator, pre-collected: no heap
/// allocator is touched anywhere in this shell.
pub fn maybeRun(io: std.Io, args: []const [:0]const u8) !bool {
    if (args.len < 2 or !std.mem.eql(u8, args[1], "ca")) return false;
    dispatch(io, args[2..]) catch |e| {
        std.debug.print("bolina ca: {s} (SPEC D-091 section 5)\n", .{@errorName(e)});
        std.process.exit(1);
    };
    return true;
}

fn dispatch(io: std.Io, args: []const [:0]const u8) !void {
    if (args.len == 0) return error.UnknownCommand;
    const cmd = args[0];
    var fl: Flags = .{};
    var i: usize = 1;
    while (i < args.len) : (i += 2) {
        const a: []const u8 = args[i];
        if (a.len < 3 or !std.mem.startsWith(u8, a, "--")) return error.UnknownCommand;
        if (i + 1 >= args.len) return error.MissingFlagValue;
        try fl.set(a, args[i + 1]);
    }
    if (std.mem.eql(u8, cmd, "init"))
        return material.caInit(io, try require(fl.dir), fl.count);
    if (std.mem.eql(u8, cmd, "issue")) {
        _ = try material.caIssue(io, .{
            .ca_dir = try require(fl.ca_dir),
            .node_dir = try require(fl.node_dir),
            .role_bits = try material.roleFromString(try require(fl.role)),
            .ttl_ms = if (fl.ttl) |t| try parseTtl(t) else 15 * 86_400_000,
            .name = fl.name orelse "",
            .scopes = fl.scopes[0..fl.scope_count],
        });
        return;
    }
    if (std.mem.eql(u8, cmd, "revoke"))
        return material.caRevoke(io, try require(fl.ca_dir), try require(fl.serial), fl.subject_expiry_ms, try require(fl.out));
    if (std.mem.eql(u8, cmd, "list"))
        return cmdList(io, try require(fl.ca_dir));
    if (std.mem.eql(u8, cmd, "show"))
        return cmdShow(io, try require(fl.ca_dir), try require(fl.serial));
    return error.UnknownCommand;
}

fn cmdList(io: std.Io, ca_dir: []const u8) !void {
    var pbuf: [MAX_PATH]u8 = undefined;
    const issued_path = std.fmt.bufPrint(&pbuf, "{s}/issued", .{ca_dir}) catch return error.SerialNotFound;
    var dir = std.Io.Dir.cwd().openDir(io, issued_path, .{}) catch return error.SerialNotFound;
    defer dir.close(io);
    var it = dir.iterate();
    var count: usize = 0;
    while (try it.next(io)) |entry| {
        if (count >= MAX_SERIALS_LIST) break;
        std.debug.print("{s}\n", .{entry.name});
        count += 1;
    }
    if (count == 0) std.debug.print("(no issued certs)\n", .{});
}

var fp_sig: [16]u8 = undefined;
var fp_kex: [16]u8 = undefined;

fn cmdShow(io: std.Io, ca_dir: []const u8, serial: []const u8) !void {
    var raw: [1024]u8 = undefined;
    var fbuf: [MAX_PATH]u8 = undefined;
    const path = try material.issuedPath(ca_dir, serial, &fbuf);
    const f = std.Io.Dir.cwd().openFile(io, path, .{}) catch return error.SerialNotFound;
    defer f.close(io);
    const n = f.readPositionalAll(io, &raw, 0) catch return error.SerialNotFound;
    const c = session.parseCert(raw[0..n]) catch return error.SerialNotFound;
    fp_sig = keys_mod.fingerprint(c.sig_pubkey);
    fp_kex = keys_mod.fingerprint(c.kex_pubkey);
    std.debug.print(
        \\serial   {s}
        \\version  {d}
        \\roles    0x{X:0>2}
        \\sig_fp   {s}
        \\kex_fp   {s}
        \\window   {d}..{d}
        \\name     {s}
        \\scopes   {d}
        \\ca_sigs  {d}
        \\bytes    {d}
        \\
    , .{
        serial,
        c.version,
        c.role_bits,
        &fp_sig,
        &fp_kex,
        c.not_before,
        c.not_after,
        c.name,
        c.scope_count,
        c.ca_sig_count,
        n,
    });
}
