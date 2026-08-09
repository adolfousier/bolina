// reassembly.zig
//
// LANGUAGE.md section 4 implementation slice, transport item: fragment
// reassembly under the declared BE-TR-05 limits (SPEC.md section 4.4 table and
// section 4.5 Fragmentation). Messages larger than the packet limit are split by
// the sender into a flat header (msg_id:u64, index:u16, total:u16) plus payload,
// reassembled at the receiver, and discarded after a 30-second incomplete
// timeout. Fragments are AEAD-protected like any packet; there is no
// unauthenticated fragmentation, so this module handles authenticated fragments.
//
// The limits are stated as one table because they must agree, and in an earlier
// draft they did not: per-peer 8 MiB with no ceiling on peers left total memory
// unbounded on exactly the nodes (lighthouses, relays) that face the most peers.
// So there are two scopes, with two different failure semantics:
//
//   * Message-level (per peer): at most 8 concurrent incomplete contexts and
//     8 MiB of reassembly memory. Breaching a message-level limit drops the
//     message, and MUST NOT drop the session. The peer stays connected; only the
//     offending reassembly is torn down.
//   * Node-level: at most 512 concurrent sessions and 256 MiB of reassembly
//     memory in aggregate. Breaching a node-level limit MUST refuse new sessions
//     rather than degrade existing ones, and MUST surface as a capacity
//     condition, never silently absorbed.
//
// Zero-heap and caller-owned (BE-WIRE-01). This module tracks reassembly STATE:
// which fragment indices have arrived, how many bytes a peer is holding, whether
// a context has timed out, whether a node can admit another session. It stores
// NO payload bytes. The caller owns the byte buffers and places fragments into
// them; this module answers the accounting and limit questions on top. That
// keeps the metadata-only structures small (the real instance is roughly a
// kilobyte, not 8 MiB) and matches D-018: state over parsed values lives in
// transport, outside the parser M5 budget. PeerReassembler is generic over the
// context count and the per-message fragment ceiling so tests exercise the
// limits with tiny structures and production instantiates the real BE-TR-05
// values.

const std = @import("std");

// ---- BE-TR-05 declared limits (SPEC.md section 4.4 table) ----
// The single source of truth for every attacker-influenced buffer size.
pub const MAX_MESSAGE: usize = 1 << 20; // 1 MiB: the ceiling every size derives from
pub const MAX_HEADER: usize = 512; // envelope overhead
pub const MAX_BODY_LEN: usize = MAX_MESSAGE - MAX_HEADER; // so a max envelope is deliverable
pub const CONTEXTS_PER_PEER: u8 = 8;
pub const MEMORY_PER_PEER: usize = 8 << 20; // 8 MiB
pub const SESSIONS_PER_NODE: u16 = 512; // default
pub const MEMORY_PER_NODE: usize = 256 << 20; // 256 MiB default, independent of peer count
pub const INCOMPLETE_TIMEOUT_MS: u64 = 30_000; // 30 s

// ---- Per-fragment outcomes (message scope) ----
pub const PeerEvent = enum {
    complete, // last distinct fragment arrived; message reassembled, context freed
    partial, // fragment accepted, more expected
    duplicate, // fragment index already seen: counted once, no state change
    message_dropped, // peer limit breach (too many contexts, too much memory) or malformed: drop the message, keep the session
};

// ---- Node admission outcomes (node scope) ----
pub const NodeEvent = enum {
    admitted, // new session accepted
    refused, // node limit breach (sessions or memory): capacity condition, surface it
};

// Per-peer fragment reassembly under the BE-TR-05 message-level limits. Generic
// over the context count and the per-message fragment ceiling so tests use small
// structures; production passes CONTEXTS_PER_PEER and a fragment ceiling.
pub fn PeerReassembler(comptime max_contexts: u8, comptime max_fragments_per_msg: u16) type {
    const frag_words = (max_fragments_per_msg + 63) / 64;

    return struct {
        const Self = @This();
        pub const MAX_CONTEXTS = max_contexts;
        pub const MAX_FRAGMENTS = max_fragments_per_msg;

        const Bitset = [frag_words]u64;

        // One incomplete message. Metadata only; the caller holds the payload.
        pub const Context = struct {
            msg_id: u64 = 0,
            total: u16 = 0,
            received: u16 = 0, // count of distinct fragment indices seen
            bytes: usize = 0, // accumulated fragment payload bytes
            updated_ms: u64 = 0,
            in_use: bool = false,
            seen: Bitset = std.mem.zeroes(Bitset),
        };

        contexts: [max_contexts]Context = std.mem.zeroes([max_contexts]Context),
        active: u8 = 0,
        bytes_used: usize = 0, // sum of active contexts' bytes

        pub fn init() Self {
            return .{};
        }

        pub fn activeContexts(self: Self) u8 {
            return self.active;
        }

        pub fn bytesInUse(self: Self) usize {
            return self.bytes_used;
        }

        // Ingest one authenticated fragment. Updates state and returns the
        // outcome. A breach returns message_dropped and tears down the message's
        // context; the session is unaffected.
        pub fn ingest(self: *Self, now_ms: u64, msg_id: u64, index: u16, total: u16, frag_bytes: usize) PeerEvent {
            // A total of zero or an index outside it is malformed wire for this
            // message; a total beyond the fragment ceiling cannot be tracked.
            if (total == 0 or index >= total or total > max_fragments_per_msg) return .message_dropped;

            // Find an existing context for this msg_id, else a free slot.
            var ctx: ?*Context = null;
            for (&self.contexts) |*c| {
                if (c.in_use and c.msg_id == msg_id) {
                    ctx = c;
                    break;
                }
            }
            const creating = ctx == null;
            if (creating) {
                if (self.active >= max_contexts) return .message_dropped; // peer context limit
                for (&self.contexts) |*c| {
                    if (!c.in_use) {
                        c.* = .{ .in_use = true, .msg_id = msg_id, .total = total, .updated_ms = now_ms };
                        self.active += 1;
                        ctx = c;
                        break;
                    }
                }
                if (ctx == null) return .message_dropped; // no free slot (should not happen)
            }

            const c = ctx.?;
            // A second fragment disagreeing on total is malformed for this message.
            if (c.total != total) {
                self.freeContext(c);
                return .message_dropped;
            }

            // Duplicate index: counted once, no byte accounting, no completion.
            if (bsGet(c.seen, index)) {
                c.updated_ms = now_ms;
                return .duplicate;
            }

            // Per-message and per-peer memory limits. Either breach drops the
            // whole message (releasing its accumulated bytes), not the session.
            if (c.bytes + frag_bytes > MAX_MESSAGE) {
                self.freeContext(c);
                return .message_dropped;
            }
            if (self.bytes_used + frag_bytes > MEMORY_PER_PEER) {
                self.freeContext(c);
                return .message_dropped;
            }

            bsSet(&c.seen, index);
            c.received += 1;
            c.bytes += frag_bytes;
            self.bytes_used += frag_bytes;
            c.updated_ms = now_ms;

            if (c.received >= c.total) {
                self.freeContext(c); // delivered: release context and its bytes
                return .complete;
            }
            return .partial;
        }

        // Drop contexts whose last update is older than the incomplete timeout.
        // Returns how many were torn down.
        pub fn evictExpired(self: *Self, now_ms: u64) u8 {
            var evicted: u8 = 0;
            for (&self.contexts) |*c| {
                if (c.in_use and (now_ms -% c.updated_ms) >= INCOMPLETE_TIMEOUT_MS) {
                    self.freeContext(c);
                    evicted += 1;
                }
            }
            return evicted;
        }

        // Release a context back to the pool and return its bytes to the peer
        // budget. Used on completion, drop, and timeout.
        fn freeContext(self: *Self, c: *Context) void {
            self.bytes_used -= c.bytes;
            self.active -= 1;
            c.in_use = false;
            c.received = 0;
            c.total = 0;
            c.bytes = 0;
            c.msg_id = 0;
        }

        fn bsSet(seen: *Bitset, idx: u16) void {
            seen[idx / 64] |= @as(u64, 1) << @intCast(idx % 64);
        }
        fn bsGet(seen: Bitset, idx: u16) bool {
            return (seen[idx / 64] & (@as(u64, 1) << @intCast(idx % 64))) != 0;
        }
    };
}

// Node-level admission and memory gate (BE-TR-05 node scope). The caller
// aggregates per-peer bytes into this counter and asks before admitting a new
// session or growing reassembly memory.
pub const NodeCapacity = struct {
    sessions: u16 = 0,
    bytes_used: usize = 0,

    pub fn init() NodeCapacity {
        return .{};
    }

    // Admit a new session unless the node session ceiling is reached. A refusal
    // is a capacity condition the caller MUST surface, not silently absorb.
    pub fn tryAdmitSession(self: *NodeCapacity) NodeEvent {
        if (self.sessions >= SESSIONS_PER_NODE) return .refused;
        self.sessions += 1;
        return .admitted;
    }

    pub fn releaseSession(self: *NodeCapacity) void {
        if (self.sessions > 0) self.sessions -= 1;
    }

    // Would adding `bytes` of reassembly memory stay under the node ceiling?
    pub fn withinMemory(self: NodeCapacity, bytes: usize) bool {
        return bytes <= MEMORY_PER_NODE -% self.bytes_used;
    }

    pub fn addBytes(self: *NodeCapacity, bytes: usize) void {
        self.bytes_used += bytes;
    }

    pub fn releaseBytes(self: *NodeCapacity, bytes: usize) void {
        if (bytes <= self.bytes_used) self.bytes_used -= bytes else self.bytes_used = 0;
    }
};
