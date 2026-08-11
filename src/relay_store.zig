// relay_store.zig
//
// Relay store-and-forward engine (SPEC.md section 5.2a store-and-forward
// clause, BE-MESH-03, D-058). Non-surface, state over parsed values (D-018,
// placed ahead of code by D-058): the relay layer hands this module a sender
// index, a recipient overlay_addr, and opaque ciphertext bytes, and this
// module never parses the body (BE-MESH-02 opacity).
//
// Bounds are declared in SPEC v0.3.4-draft: at most 64 stored packets and
// 4 MiB in aggregate per recipient, body at most 2048 bytes, TTL 72 hours,
// 1024 global slots. Quota exhaustion refuses the store and counts it; live
// forwarding is never blocked. TTL purge is lazy, driven by the caller's
// clock (now_ms): no timers before the daemon milestone.
//
// Storage keys by overlay_addr, not client_index (D-058): indexes die with
// the session, overlay_addr persists (BE-ID-01). Drain returns packets in
// storage order; the relay-layer recipient_index rewrite happens at the
// caller under the D-058 warrant, never here.

const std = @import("std");

// Declared bounds (SPEC.md section 5.2a, D-058).
pub const MAX_BODY: usize = 2048;
pub const MAX_PER_RECIPIENT: usize = 64;
pub const MAX_BYTES_PER_RECIPIENT: usize = 4 * 1024 * 1024;
pub const TTL_MS: u64 = 72 * 60 * 60 * 1000;
pub const MAX_STORED: usize = 1024;

pub const StoreError = error{
    BodyTooLarge, // body exceeds the declared 2048-byte cap
    RecipientQuota, // 64 packets (or the byte bound) already stored for this recipient
    StoreFull, // 1024 slots occupied across the store
};

pub const StoredPacket = struct {
    in_use: bool = false,
    sender_index: u32 = 0, // route-header sender index at store time
    recipient_addr: [16]u8 = undefined, // overlay_addr key (BE-ID-01, D-058)
    body_len: usize = 0,
    body: [MAX_BODY]u8 = undefined, // ciphertext, opaque, byte-for-byte
    stored_at_ms: u64 = 0, // caller clock at store time
};

pub const DrainedPacket = struct {
    sender_index: u32,
    body: []const u8, // borrows slot storage until the next store() call
};

pub const Store = struct {
    packets: [MAX_STORED]StoredPacket = undefined,
    count: usize = 0,
    refused_quota: u64 = 0, // surfaced counter (SPEC clause: count, never block)

    // reset (D-058): the slot array carries no element defaults, so init
    // walks it once. Callers hold the Store; nothing is returned by value.
    pub fn reset(self: *Store) void {
        for (&self.packets) |*p| p.in_use = false;
        self.count = 0;
        self.refused_quota = 0;
    }

    // store (BE-MESH-03): bounded by the declared constants. Quota
    // exhaustion refuses the store and counts it; nothing here ever blocks
    // live forwarding, because nothing here forwards. The byte bound is
    // defense-in-depth under the current constants: 64 packets at a 2048
    // byte body cap top out at 128 KiB, so the packet bound binds first.
    pub fn store(self: *Store, recipient_addr: [16]u8, sender_index: u32, body: []const u8, now_ms: u64) StoreError!void {
        if (body.len > MAX_BODY) return error.BodyTooLarge;
        _ = self.purgeExpired(now_ms);
        if (self.count >= MAX_STORED) {
            self.refused_quota += 1;
            return error.StoreFull;
        }
        var recip_count: usize = 0;
        var recip_bytes: usize = 0;
        for (&self.packets) |*p| {
            if (!p.in_use) continue;
            if (!std.mem.eql(u8, &p.recipient_addr, &recipient_addr)) continue;
            recip_count += 1;
            recip_bytes += p.body_len;
        }
        if (recip_count >= MAX_PER_RECIPIENT or recip_bytes + body.len > MAX_BYTES_PER_RECIPIENT) {
            self.refused_quota += 1;
            return error.RecipientQuota;
        }
        for (&self.packets) |*p| {
            if (p.in_use) continue;
            p.in_use = true;
            p.sender_index = sender_index;
            p.recipient_addr = recipient_addr;
            p.body_len = body.len;
            @memcpy(p.body[0..body.len], body);
            p.stored_at_ms = now_ms;
            self.count += 1;
            return;
        }
        // Unreachable: count below MAX_STORED guarantees a free slot.
        self.refused_quota += 1;
        return error.StoreFull;
    }

    // drainNext (BE-MESH-03, D-058): oldest stored packet for the recipient,
    // storage order out, body untouched. Returns null when the queue is
    // empty. The body slice borrows slot storage: forward it before the
    // next store() call.
    pub fn drainNext(self: *Store, recipient_addr: [16]u8, now_ms: u64) ?DrainedPacket {
        _ = self.purgeExpired(now_ms);
        var best: ?usize = null;
        for (&self.packets, 0..) |*p, i| {
            if (!p.in_use) continue;
            if (!std.mem.eql(u8, &p.recipient_addr, &recipient_addr)) continue;
            if (best) |b| {
                if (p.stored_at_ms > self.packets[b].stored_at_ms) continue;
                if (p.stored_at_ms == self.packets[b].stored_at_ms and i > b) continue;
            }
            best = i;
        }
        const idx = best orelse return null;
        const p = &self.packets[idx];
        const out = DrainedPacket{ .sender_index = p.sender_index, .body = p.body[0..p.body_len] };
        p.in_use = false;
        self.count -= 1;
        return out;
    }

    // purgeExpired (D-058): lazy TTL purge against the caller's clock.
    pub fn purgeExpired(self: *Store, now_ms: u64) usize {
        var purged: usize = 0;
        for (&self.packets) |*p| {
            if (!p.in_use) continue;
            if (now_ms >= p.stored_at_ms and now_ms - p.stored_at_ms >= TTL_MS) {
                p.in_use = false;
                self.count -= 1;
                purged += 1;
            }
        }
        return purged;
    }
};
