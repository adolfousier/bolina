// ca_material.zig
//
// Offline CA material layer (D-091 section 5): mint roots, issue SPEC 3.1
// certs for existing node identities, emit BE-CTRL-03 Revoke bodies. No
// argv, no network, no daemon state: pure file-and-bytes operations over the
// formats keys.zig and binding.zig already consume, so anything produced here
// is accepted by the daemon by construction. ca_cli.zig is the thin argv
// shell over these functions; tests call them directly.
//
// Serial (F7): BLAKE2s-256(cert tbs)[0..16] hex, 32 chars - deterministic
// from the cert bytes, recomputable by anyone holding the cert.
//
// Issued certs are archived under <ca-dir>/issued/<serial>.cert in the same
// wire format so revoke/list/show resolve a serial without inventing a
// database. Revoke bodies default the subject expiry to the subject cert's
// own not_after, the exact value D-090 pruning consumes.

const std = @import("std");
const keys_mod = @import("keys.zig");
const binding = @import("binding.zig");
const session = @import("parser/session.zig");

const Ed = std.crypto.sign.Ed25519;
const B2s = std.crypto.hash.blake2.Blake2s256;
pub const DOMAIN_CERT = session.DOMAIN_CERT; // 0x01 over cert.tbs (BE-SIG-01)
const KEY_LEN = keys_mod.KEY_LEN;
const MAX_CERT = keys_mod.MAX_CERT;
const MAX_PATH = keys_mod.MAX_PATH;

pub const Error = error{
    BadRole,
    BadTtl,
    BadCount,
    BadSerial,
    TtlOverCap,
    NoCaKeys,
    TooManyCas,
    CertUnreadable,
    NameTooLong,
    DataDirUnwritable,
};

pub fn joinPath(out: []u8, base: []const u8, name: []const u8) Error![]const u8 {
    return std.fmt.bufPrint(out, "{s}/{s}", .{ base, name }) catch error.CertUnreadable;
}

fn readFileFull(io: std.Io, path: []const u8, out: []u8) Error![]const u8 {
    const dir = std.Io.Dir.cwd();
    const f = dir.openFile(io, path, .{}) catch return error.CertUnreadable;
    defer f.close(io);
    const n = f.readPositionalAll(io, out[0..@min(out.len, MAX_CERT)], 0) catch return error.CertUnreadable;
    return out[0..n];
}

fn hexSerial(digest: *const [16]u8) [32]u8 {
    var hex: [32]u8 = undefined;
    const chars = "0123456789abcdef";
    for (0..16) |i| {
        hex[i * 2] = chars[digest[i] >> 4];
        hex[i * 2 + 1] = chars[digest[i] & 0xf];
    }
    return hex;
}

/// Serial of a cert tbs: full BLAKE2s-256 digest truncated to 16 bytes,
/// same shape as keys.fingerprint.
pub fn serialOf(tbs: []const u8) [32]u8 {
    var full: [32]u8 = undefined;
    var half: [16]u8 = undefined;
    B2s.hash(tbs, &full, .{});
    @memcpy(&half, full[0..16]);
    return hexSerial(&half);
}

// Flat libc clock seam, same house pattern as main.zig (importing main from
// here would be a cycle). Wall time on purpose: validity windows are absolute
// (BE-ID-02).
extern "c" fn clock_gettime(clk_id: c_int, tp: *Timespec) c_int;
const CLOCK_REALTIME: c_int = 0;
const Timespec = extern struct { sec: c_long, nsec: c_long };
fn wallMs() u64 {
    var ts: Timespec = undefined;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) return 0;
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(@divTrunc(ts.nsec, 1_000_000)));
}

fn ensureDir(io: std.Io, path: []const u8) !void {
    std.Io.Dir.cwd().createDir(io, path, @enumFromInt(0o700)) catch |e| switch (e) {
        error.PathAlreadyExists => {},
        else => return error.DataDirUnwritable,
    };
}

/// Mint `count` Ed25519 roots: `ca{i}.key` (0600 seeds) beside `ca/ca{i}.pub`
/// trust anchors, exactly the layout keys.loadCas consumes at daemon boot.
pub fn caInit(io: std.Io, dir_path: []const u8, count: usize) !void {
    if (count == 0 or count > keys_mod.MAX_CAS) return error.BadCount;
    try ensureDir(io, dir_path);
    var ca_buf: [MAX_PATH]u8 = undefined;
    const ca_sub = try joinPath(&ca_buf, dir_path, "ca");
    try ensureDir(io, ca_sub);
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const kp = Ed.KeyPair.generate(io);
        const seed = kp.secret_key.seed();
        const public = Ed.PublicKey.toBytes(kp.public_key);
        var kb: [MAX_PATH]u8 = undefined;
        var pb: [MAX_PATH]u8 = undefined;
        var lb: [16]u8 = undefined;
        const key_path = try joinPath(&kb, dir_path, std.fmt.bufPrint(&lb, "ca{d}.key", .{i}) catch unreachable);
        try keys_mod.writeKeyFile(io, key_path, &seed);
        const pub_path = try joinPath(&pb, ca_sub, std.fmt.bufPrint(&lb, "ca{d}.pub", .{i}) catch unreachable);
        try keys_mod.writeKeyFile(io, pub_path, &public);
        std.debug.print("ca{d}: fp {s}\n", .{ i, keys_mod.fingerprint(&public) });
    }
    std.debug.print("init: {d} root(s) under {s}, trust anchors in {s}/\n", .{ count, dir_path, ca_sub });
}

pub fn roleFromString(s: []const u8) Error!u8 {
    if (std.mem.eql(u8, s, "agent")) return binding.ROLE_AGENT;
    if (std.mem.eql(u8, s, "executor")) return binding.ROLE_EXECUTOR;
    if (std.mem.eql(u8, s, "approver")) return binding.ROLE_APPROVER;
    return error.BadRole;
}

pub const IssueReq = struct {
    ca_dir: []const u8,
    node_dir: []const u8,
    role_bits: u8,
    ttl_ms: u64,
    name: []const u8 = "",
    scopes: []const [8]u8 = &.{},
};

pub const IssueResult = struct { serial_hex: [32]u8 };

/// Load every root key under `<ca-dir>/ca{i}.key`, returning keypairs whose
/// pubkeys are sorted strictly ascending (parseCert rejects any other order).
fn loadCaKeys(io: std.Io, ca_dir: []const u8, kps: *[session.MAX_CA_SIGS]Ed.KeyPair, pubs: *[session.MAX_CA_SIGS][KEY_LEN]u8) Error!usize {
    var n: usize = 0;
    var i: usize = 0;
    while (i < keys_mod.MAX_CAS) : (i += 1) {
        if (n >= session.MAX_CA_SIGS) return error.TooManyCas;
        var key: [KEY_LEN]u8 = undefined;
        var kb: [MAX_PATH]u8 = undefined;
        var lb: [16]u8 = undefined;
        const key_path = try joinPath(&kb, ca_dir, std.fmt.bufPrint(&lb, "ca{d}.key", .{i}) catch unreachable);
        if (!(keys_mod.readKeyFile(io, key_path, &key) catch return error.CertUnreadable)) continue;
        const kp = Ed.KeyPair.generateDeterministic(key) catch return error.CertUnreadable;
        kps[n] = kp;
        pubs[n] = Ed.PublicKey.toBytes(kp.public_key);
        n += 1;
    }
    // Selection sort by pubkey bytes; MAX_CA_SIGS is 4, cycles are free.
    var a: usize = 0;
    while (a + 1 < n) : (a += 1) {
        var b: usize = a + 1;
        while (b < n) : (b += 1) {
            if (std.mem.order(u8, &pubs[b], &pubs[a]) == .lt) {
                const tk = kps[a];
                kps[a] = kps[b];
                kps[b] = tk;
                const tp = pubs[a];
                pubs[a] = pubs[b];
                pubs[b] = tp;
            }
        }
    }
    return n;
}

/// Build and sign one SPEC 3.1 cert for an existing node identity, install it
/// as the node's cert.bin, archive a copy under <ca-dir>/issued/<serial>.cert.
pub fn caIssue(io: std.Io, req: IssueReq) !IssueResult {
    const role_bits = req.role_bits;
    // BE-ID-03 is a receipt check too; at issuance the CA refuses early so a
    // compromised CA cannot even mint a self-approving identity locally.
    binding.checkRoleConstraints(role_bits) catch return error.BadRole;
    // BE-REV-01: privileged spans are capped at the source, not left to peers.
    const ttl = req.ttl_ms;
    if ((role_bits & (binding.ROLE_APPROVER | binding.ROLE_EXECUTOR)) != 0 and
        ttl > binding.MAX_PRIVILEGED_LIFETIME_MS) return error.TtlOverCap;

    var sig_pub: [KEY_LEN]u8 = undefined;
    var kex_pub: [KEY_LEN]u8 = undefined;
    var sig_buf: [MAX_PATH]u8 = undefined;
    var kex_buf: [MAX_PATH]u8 = undefined;
    const sig_path = try joinPath(&sig_buf, req.node_dir, "sig.pub");
    const kex_path = try joinPath(&kex_buf, req.node_dir, "static.pub");
    if (!try keys_mod.readKeyFile(io, sig_path, &sig_pub)) return error.CertUnreadable;
    if (!try keys_mod.readKeyFile(io, kex_path, &kex_pub)) return error.CertUnreadable;

    var kps: [session.MAX_CA_SIGS]Ed.KeyPair = undefined;
    var pubs: [session.MAX_CA_SIGS][KEY_LEN]u8 = undefined;
    const n_cas = try loadCaKeys(io, req.ca_dir, &kps, &pubs);
    if (n_cas == 0) return error.NoCaKeys;

    // tbs (SPEC 3.1): version | role_bits | sig_pub | kex_pub | nb | na |
    // u16be name_len,name | scope_count,scope_ids.
    const now = wallMs();
    var wire: [MAX_CERT]u8 = undefined;
    var n: usize = 0;
    wire[n] = 2; // version 2 (Grant.version==2 convention, SPEC 2.2)
    n += 1;
    wire[n] = role_bits;
    n += 1;
    @memcpy(wire[n..][0..KEY_LEN], &sig_pub);
    n += KEY_LEN;
    @memcpy(wire[n..][0..KEY_LEN], &kex_pub);
    n += KEY_LEN;
    std.mem.writeInt(u64, wire[n..][0..8], now, .big);
    n += 8;
    std.mem.writeInt(u64, wire[n..][0..8], now + ttl, .big);
    n += 8;
    const name = req.name;
    if (name.len > session.MAX_NAME) return error.NameTooLong;
    std.mem.writeInt(u16, wire[n..][0..2], @intCast(name.len), .big);
    n += 2;
    @memcpy(wire[n..][0..name.len], name);
    n += name.len;
    if (req.scopes.len > session.MAX_SCOPE) return error.NameTooLong;
    wire[n] = @intCast(req.scopes.len);
    n += 1;
    for (req.scopes) |sc| {
        @memcpy(wire[n..][0..8], &sc);
        n += 8;
    }
    const tbs_len = n;
    const tbs = wire[0..tbs_len];

    // CA signatures over (DOMAIN_CERT || tbs), pairs in ascending key order.
    var msg: [1 + MAX_CERT]u8 = undefined;
    msg[0] = DOMAIN_CERT;
    @memcpy(msg[1..][0..tbs_len], tbs);
    wire[n] = @intCast(n_cas);
    n += 1;
    for (0..n_cas) |k| {
        const sig = kps[k].sign(msg[0 .. 1 + tbs_len], null) catch return error.CertUnreadable;
        @memcpy(wire[n..][0..KEY_LEN], &pubs[k]);
        n += KEY_LEN;
        @memcpy(wire[n..][0..64], &Ed.Signature.toBytes(sig));
        n += 64;
    }
    const cert_bytes = wire[0..n];

    var cb: [MAX_PATH]u8 = undefined;
    const cert_path = try joinPath(&cb, req.node_dir, "cert.bin");
    try keys_mod.writeKeyFile(io, cert_path, cert_bytes);

    const serial = serialOf(tbs);
    var ib: [MAX_PATH]u8 = undefined;
    const issued_dir_path = try joinPath(&ib, req.ca_dir, "issued");
    try ensureDir(io, issued_dir_path);
    var sb: [MAX_PATH]u8 = undefined;
    const arch_path = try joinPath(&sb, issued_dir_path, &serial);
    try keys_mod.writeKeyFile(io, arch_path, cert_bytes);

    std.debug.print("issue: serial {s} roles 0x{X:0>2} ttl {d}ms cas {d} -> {s}\n", .{ serial, role_bits, ttl, n_cas, cert_path });
    return .{ .serial_hex = serial };
}

pub fn issuedPath(ca_dir: []const u8, serial: []const u8, buf: []u8) Error![]const u8 {
    if (serial.len != 32) return error.BadSerial;
    for (serial) |ch| {
        const ok = (ch >= '0' and ch <= '9') or (ch >= 'a' and ch <= 'f');
        if (!ok) return error.BadSerial;
    }
    var pbuf: [MAX_PATH]u8 = undefined;
    const issued = try joinPath(&pbuf, ca_dir, "issued");
    return joinPath(buf, issued, serial);
}

/// Emit the BE-CTRL-03 Revoke Control body for a serial issued by this CA.
/// subject_expiry_ms null defaults to the subject cert's own not_after (the
/// value D-090 pruning consumes).
pub fn caRevoke(io: std.Io, ca_dir: []const u8, serial: []const u8, subject_expiry_ms: ?u64, out_path: []const u8) !void {
    var fbuf: [MAX_PATH]u8 = undefined;
    const arch_path = try issuedPath(ca_dir, serial, &fbuf);
    var raw: [MAX_CERT]u8 = undefined;
    const bytes = try readFileFull(io, arch_path, &raw);
    const cert = session.parseCert(bytes) catch return error.CertUnreadable;
    const expiry = subject_expiry_ms orelse cert.not_after;
    var body: [44]u8 = undefined;
    body[0] = 1; // Control version (SPEC 6.1c fixtures carry 01)
    body[1] = 2; // action_type Revoke (BE-CTRL-01)
    @memcpy(body[2..34], cert.sig_pubkey[0..32]);
    std.mem.writeInt(u16, body[34..36], 8, .big); // body_len
    std.mem.writeInt(u64, body[36..44], expiry, .big);
    try keys_mod.writeKeyFile(io, out_path, &body);
    std.debug.print("revoke: subject fp {s} expiry {d}ms -> {s}\n", .{ keys_mod.fingerprint(cert.sig_pubkey), expiry, out_path });
}
