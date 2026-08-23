// keys.zig
//
// Node key material (D-018, daemon closeout D-089 section 1). Nothing here is
// ever hardcoded: on first run both keypairs are generated from the
// platform RNG and persisted under the data dir with owner-only
// permissions; on later runs the secrets are loaded and the publics
// re-derived, with the stored public files cross-checked (a tampered or
// mismatched public is a distinct fatal error, never silently accepted).
// Log lines carry fingerprints (public key hex) only: no secret byte ever
// reaches a log.
//
// Layout under $BOLINA_DATA_DIR (D-089):
//   static.key / static.pub   X25519 Noise_IK static, 32B raw
//   sig.key    / sig.pub      Ed25519 identity seed, 32B raw
//   cert.bin                  own CA-issued certificate, wire format
//   ca/ca0.pub .. ca/ca7.pub  trusted CA signing keys, 32B raw each
//
// cert.bin is deliberately NOT self-generated: a node without a CA-issued
// cert runs unbound-accept (handshakes complete, binding fails on inbound
// peers, outbound binding is impossible). The conformance pilot carries a
// test CA. Fixed caN.pub labels keep loading deterministic; the cap is 8.

const std = @import("std");

pub const MAX_CAS: usize = 8;
pub const MAX_CERT: usize = 1024;
pub const KEY_LEN: usize = 32;
pub const MAX_PATH: usize = 256;

pub const KeysError = error{
    DataDirUnwritable, // mkdir on the data dir failed for a non-already-exists reason
    KeyFileCorrupt, // a key file exists but is not exactly 32 bytes
    PubMismatch, // stored public does not match the secret (tamper or corruption)
    CertTooLarge, // cert.bin exceeds MAX_CERT
    DiskError, // a file operation failed
};

pub const Keys = struct {
    kex_secret: [KEY_LEN]u8,
    kex_public: [KEY_LEN]u8,
    sig_seed: [KEY_LEN]u8,
    sig_public: [KEY_LEN]u8,
    // Absent cert = len 0: unbound-accept mode (D-089 section 1).
    own_cert: [MAX_CERT]u8,
    own_cert_len: usize,
    trusted_ca_keys: [MAX_CAS][KEY_LEN]u8,
    trusted_ca_count: usize,
};

fn joinPath(out: []u8, base: []const u8, name: []const u8) KeysError![]const u8 {
    return std.fmt.bufPrint(out, "{s}/{s}", .{ base, name }) catch return error.DiskError;
}

// Read exactly KEY_LEN bytes from one key file. Any other length is
// corruption, not a format evolution: the files are raw fixed-size keys.
// pub for ca_cli (D-091 section 5): one home for the key-file discipline.
pub fn readKeyFile(io: std.Io, path: []const u8, out: *[KEY_LEN]u8) KeysError!bool {
    const dir = std.Io.Dir.cwd();
    const f = dir.openFile(io, path, .{}) catch |e| switch (e) {
        error.FileNotFound => return false,
        else => return error.DiskError,
    };
    defer f.close(io);
    const n = f.readPositionalAll(io, out, 0) catch return error.DiskError;
    if (n != KEY_LEN) return error.KeyFileCorrupt;
    return true;
}

pub fn writeKeyFile(io: std.Io, path: []const u8, bytes: []const u8) KeysError!void {
    const dir = std.Io.Dir.cwd();
    const f = dir.createFile(io, path, .{ .read = true, .truncate = true, .permissions = @enumFromInt(0o600) }) catch return error.DiskError;
    defer f.close(io);
    f.writePositionalAll(io, bytes, 0) catch return error.DiskError;
}

// Load-or-generate one X25519 static pair. The public is always derived
// from the secret (a stored public file is only a cross-check), so a
// flipped public file cannot redirect identity.
fn loadOrGenerateX25519(io: std.Io, dir_path: []const u8) KeysError!struct { secret: [KEY_LEN]u8, public: [KEY_LEN]u8 } {
    var path_buf: [MAX_PATH]u8 = undefined;
    const secret_path = try joinPath(&path_buf, dir_path, "static.key");
    var secret: [KEY_LEN]u8 = undefined;
    if (!try readKeyFile(io, secret_path, &secret)) {
        const kp = std.crypto.dh.X25519.KeyPair.generate(io);
        secret = kp.secret_key;
        try writeKeyFile(io, secret_path, &secret);
    }
    const public = std.crypto.dh.X25519.recoverPublicKey(secret) catch return error.KeyFileCorrupt;
    const pub_path = try joinPath(&path_buf, dir_path, "static.pub");
    var stored_pub: [KEY_LEN]u8 = undefined;
    if (try readKeyFile(io, pub_path, &stored_pub)) {
        if (!std.crypto.timing_safe.eql([KEY_LEN]u8, stored_pub, public)) return error.PubMismatch;
    } else {
        try writeKeyFile(io, pub_path, &public);
    }
    return .{ .secret = secret, .public = public };
}

// Load-or-generate the Ed25519 identity pair, same discipline as X25519.
fn loadOrGenerateEd25519(io: std.Io, dir_path: []const u8) KeysError!struct { seed: [KEY_LEN]u8, public: [KEY_LEN]u8 } {
    var path_buf: [MAX_PATH]u8 = undefined;
    const seed_path = try joinPath(&path_buf, dir_path, "sig.key");
    var seed: [KEY_LEN]u8 = undefined;
    if (!try readKeyFile(io, seed_path, &seed)) {
        const kp = std.crypto.sign.Ed25519.KeyPair.generate(io);
        seed = kp.secret_key.seed();
        try writeKeyFile(io, seed_path, &seed);
    }
    const kp = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed) catch return error.KeyFileCorrupt;
    const public = std.crypto.sign.Ed25519.PublicKey.toBytes(kp.public_key);
    const pub_path = try joinPath(&path_buf, dir_path, "sig.pub");
    var stored_pub: [KEY_LEN]u8 = undefined;
    if (try readKeyFile(io, pub_path, &stored_pub)) {
        if (!std.crypto.timing_safe.eql([KEY_LEN]u8, stored_pub, public)) return error.PubMismatch;
    } else {
        try writeKeyFile(io, pub_path, &public);
    }
    return .{ .seed = seed, .public = public };
}

fn loadCert(io: std.Io, dir_path: []const u8, buf: []u8) KeysError!usize {
    var path_buf: [MAX_PATH]u8 = undefined;
    const cert_path = try joinPath(&path_buf, dir_path, "cert.bin");
    const dir = std.Io.Dir.cwd();
    const f = dir.openFile(io, cert_path, .{}) catch |e| switch (e) {
        error.FileNotFound => return 0,
        else => return error.DiskError,
    };
    defer f.close(io);
    var tmp: [MAX_CERT]u8 = undefined;
    const n = f.readPositionalAll(io, &tmp, 0) catch return error.DiskError;
    if (n > MAX_CERT) return error.CertTooLarge;
    @memcpy(buf[0..n], tmp[0..n]);
    return n;
}

fn loadCas(io: std.Io, dir_path: []const u8, out: *[MAX_CAS][KEY_LEN]u8) KeysError!usize {
    var count: usize = 0;
    var label_buf: [8]u8 = undefined;
    var ca_buf: [MAX_PATH]u8 = undefined;
    const ca_dir = try joinPath(&ca_buf, dir_path, "ca");
    var path_buf: [MAX_PATH]u8 = undefined;
    var i: usize = 0;
    while (i < MAX_CAS) : (i += 1) {
        const label = std.fmt.bufPrint(&label_buf, "ca{d}.pub", .{i}) catch return error.DiskError;
        const file_path = try joinPath(&path_buf, ca_dir, label);
        var key: [KEY_LEN]u8 = undefined;
        if (!try readKeyFile(io, file_path, &key)) continue;
        out[count] = key;
        count += 1;
    }
    return count;
}

// Fingerprint: first 8 bytes of BLAKE2s(pubkey), hex. Log-safe by
// construction: the input is a public key.
pub fn fingerprint(pubkey: []const u8) [16]u8 {
    var digest: [16]u8 = undefined;
    var full: [32]u8 = undefined;
    std.crypto.hash.blake2.Blake2s256.hash(pubkey, &full, .{});
    @memcpy(&digest, full[0..16]);
    var hex: [16]u8 = undefined;
    const chars = "0123456789abcdef";
    for (0..8) |i| hex[i * 2] = chars[digest[i] >> 4];
    for (0..8) |i| hex[i * 2 + 1] = chars[digest[i] & 0xf];
    return hex;
}

// loadOrGenerate (D-089 section 3 step 3): one call, whole key material.
// The data dir is created 0700 (already-exists is fine); key files are
// written 0600. Deterministic load path: nothing regenerates over existing
// secrets.
pub fn loadOrGenerate(io: std.Io, data_dir: []const u8) KeysError!Keys {
    const dir = std.Io.Dir.cwd();
    dir.createDir(io, data_dir, @enumFromInt(0o700)) catch |e| switch (e) {
        error.PathAlreadyExists => {},
        else => return error.DataDirUnwritable,
    };
    const kex = try loadOrGenerateX25519(io, data_dir);
    const sig = try loadOrGenerateEd25519(io, data_dir);
    var keys = Keys{
        .kex_secret = kex.secret,
        .kex_public = kex.public,
        .sig_seed = sig.seed,
        .sig_public = sig.public,
        .own_cert = undefined,
        .own_cert_len = 0,
        .trusted_ca_keys = undefined,
        .trusted_ca_count = 0,
    };
    keys.own_cert_len = try loadCert(io, data_dir, &keys.own_cert);
    keys.trusted_ca_count = try loadCas(io, data_dir, &keys.trusted_ca_keys);
    return keys;
}
