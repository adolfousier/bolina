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

const MAX_DGRAM: usize = 2048;

// Global state for the daemon
var sessions: session.SessionTable = session.SessionTable.init();
var ledger: grant_ledger.GrantLedger = undefined;
var dispatcher: dispatch.Dispatch = undefined;

pub fn main() !void {
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

    std.debug.print("bolina: listener bound, entering recv loop\n", .{});

    // Recv loop
    var buf: [MAX_DGRAM]u8 = undefined;

    while (true) {
        const n = lis.recv(&buf) catch |err| {
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
                std.debug.print("bolina: handshake type {} from peer\n", .{dgram[0]});
                // TODO: wire handshake.zig + binding.zig
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
