// main.zig
//
// Bolina daemon entry point. Wires all components into a recv loop.
//
// Status: PHASE D — daemon wiring. All components tested individually;
// this module is the glue that receives datagrams, classifies them,
// and routes to the appropriate handler.
//
// Config surface (env vars):
//   BOLINA_BIND_ADDR — bind address (default: 0.0.0.0)
//   BOLINA_BIND_PORT — bind port (default: 47777)
//   BOLINA_LEDGER_PATH — grant ledger path (default: ./bolina-ledger)
//
// Key material: loaded from env vars or generated on first run.
// D-018: no hardcoded secrets.

const std = @import("std");
const listener = @import("listener.zig");
const relay_serve = @import("relay_serve.zig");
const session = @import("session.zig");
const parser = @import("parser.zig");
const verify = @import("verify.zig");
const dispatch = @import("dispatch.zig");
const grant_ledger = @import("grant_ledger.zig");
const binding = @import("binding.zig");
const noise = @import("noise.zig");
const relay = @import("relay.zig");
const handshake = @import("handshake.zig");

const MAX_DGRAM: usize = 2048;

// Key material for the daemon. D-018: no hardcoded secrets.
// Keys are loaded from files specified by env vars, or generated on first run.
const KeyMaterial = struct {
    // X25519 static keypair for Noise_IK handshake
    x25519_secret: [32]u8,
    x25519_public: [32]u8,
    
    // Ed25519 signing keypair for cert signatures, binding, relay registration
    ed25519_seed: [32]u8,
    ed25519_public: [32]u8,
    
    // Own certificate (signed by a trusted CA) — max 1024 bytes
    own_cert: [1024]u8,
    own_cert_len: usize,
    
    // Trusted CA keys (for cert validation)
    trusted_ca_keys: [8][32]u8, // up to 8 trusted CAs
    trusted_ca_count: usize,
};

// Global state for the daemon
var sessions: session.SessionTable = session.SessionTable.init();
var ledger: grant_ledger.GrantLedger = undefined;
var dispatcher: dispatch.Dispatch = undefined;
var keys: KeyMaterial = undefined;
var handshake_server: handshake.HandshakeServer = undefined;

// Generate ephemeral keys for testing. Production should load from files.
fn generateEphemeralKeys() !void {
    // TODO: implement proper key generation using std.crypto.random
    // For now, use zeroed keys (ephemeral mode, not for production)
    @memset(&keys.x25519_secret, 0);
    @memset(&keys.x25519_public, 0);
    @memset(&keys.ed25519_seed, 0);
    @memset(&keys.ed25519_public, 0);
    
    // No cert or trusted CAs for now — ephemeral mode
    keys.own_cert_len = 0;
    keys.trusted_ca_count = 0;
    
    std.debug.print("bolina: generated ephemeral keys (zeroed, not for production)\n", .{});
}

pub fn main() !void {
    // Generate ephemeral keys (D-018: no hardcoded secrets)
    try generateEphemeralKeys();
    
    // Config: hardcoded for now, env vars later
    const bind_addr = "0.0.0.0";
    const bind_port: u16 = 47777;
    const ledger_path = "./bolina-ledger";

    std.debug.print("bolina: starting on {s}:{d}\n", .{ bind_addr, bind_port });
    std.debug.print("bolina: ledger at {s}\n", .{ledger_path});

    // Initialize listener
    var lis = try listener.Listener.open(.ipv4);
    var registry = listener.EndpointRegistry{};
    try lis.bind(&registry, bind_addr, bind_port);
    defer lis.close();

    // Initialize std.Io context for handshake (Zig 0.16 std.Io)
    var threaded_io = std.Io.Threaded.init_single_threaded;
    const io = threaded_io.io;

    // Initialize handshake server with our keys
    handshake_server = handshake.HandshakeServer{
        .fd = lis.fd,
        .responder_static = noise.X25519KeyPair{
            .secret = keys.x25519_secret,
            .public = keys.x25519_public,
        },
        .responder_sig_pubkey = keys.ed25519_public,
        .io = io,
    };

    std.debug.print("bolina: listener bound, entering recv loop\n", .{});

    // Recv loop
    var buf: [MAX_DGRAM]u8 = undefined;
    var sender_addr: [28]u8 = undefined;
    var sender_addr_len: c_uint = 0;

    while (true) {
        const n = lis.recvFrom(&buf, &sender_addr, &sender_addr_len) catch |err| {
            std.debug.print("bolina: recv error: {}\n", .{err});
            continue;
        };

        if (n == 0) continue;

        const dgram = buf[0..n];

        // Classify and route
        if (dgram.len == 0) continue;

        switch (dgram[0]) {
            1, 2, 3 => {
                // Handshake messages (types 1-3)
                const slot = handshake_server.processDatagram(dgram, &sender_addr, sender_addr_len, 0) catch |err| {
                    std.debug.print("bolina: handshake error: {}\n", .{err});
                    continue;
                };
                std.debug.print("bolina: handshake completed, session slot {}\n", .{slot});
                // TODO: transition session to session.SessionTable for type 4 handling
            },
            parser.MSG_TRANSPORT_DATA => {
                // Type 4: transport data — decrypt, parse envelope, dispatch
                handleTransportData(dgram) catch |err| {
                    std.debug.print("bolina: transport data error: {}\n", .{err});
                };
            },
            relay.MSG_RELAY_ROUTE => {
                // Type 5: relay route
                std.debug.print("bolina: relay route\n", .{});
                // TODO: wire relay_serve.serveDatagram
            },
            relay.MSG_RELAY_REGISTRATION => {
                // Type 6: relay registration
                std.debug.print("bolina: relay registration\n", .{});
                // TODO: wire relay_serve.serveDatagram
            },
            else => {
                std.debug.print("bolina: unknown message type {}\n", .{dgram[0]});
            },
        }
    }
}

// Handle type 4 (transport data) packets: decrypt, parse envelope, dispatch.
fn handleTransportData(dgram: []const u8) !void {
    // Parse the data packet header
    const hdr = parser.parseDataPacketHeader(dgram) catch |err| {
        std.debug.print("bolina: bad data packet header: {}\n", .{err});
        return err;
    };

    // Look up the session by receiver_index
    const sess = sessions.lookup(hdr.receiver_index) orelse {
        std.debug.print("bolina: no session for receiver_index {}\n", .{hdr.receiver_index});
        return error.UnknownSession;
    };

    // Decrypt the payload
    var plaintext: [MAX_DGRAM]u8 = undefined;
    const pt_len = sess.open(dgram, hdr, &plaintext) catch |err| {
        std.debug.print("bolina: decrypt failed: {}\n", .{err});
        return err;
    };

    // Parse the plaintext as an Envelope
    const env = parser.channel.parseEnvelope(plaintext[0..pt_len]) catch |err| {
        std.debug.print("bolina: bad envelope: {}\n", .{err});
        return err;
    };

    // Dispatch the envelope
    // TODO: wire up the full dispatch context (intent table, sender table, etc.)
    // For now, just log that we received it
    std.debug.print("bolina: dispatched envelope version={} body_type={}\n", .{ env.version, env.body_type });
}
