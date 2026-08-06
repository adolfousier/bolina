// replay.zig
//
// LANGUAGE.md section 4 implementation slice, transport item: the sliding-window
// anti-replay filter (SPEC.md section 4.3, BE-TR-03). Each transport packet
// carries a u64 counter unique per session key, used as the AEAD nonce variable
// part (section 4.1a: nonce = [0x00 x 4] || big-endian counter). A receiver
// MUST reject a counter it has already seen or one that has fallen below the
// window, while still accepting legitimately reordered packets that land inside
// the window. UDP reorders; protection MUST NOT be "strictly increasing", which
// would drop real reordered traffic and make the protocol unusable.
//
// This is RFC 6479's sliding bitmap, at the section 4.3 floor of 1024 bits.
// The window is a 1024-bit bitmap split into sixteen 64-bit words. window[w]
// bit b (w in 0..15, b in 0..63) is set iff counter (largest - (w*64 + b)) has
// been accepted: window[0] holds the 64 most recent counters, window[15] the
// oldest still in view. largest is the highest counter seen. A counter ahead of
// largest advances the window: the bitmap is shifted left by the gap so every
// remembered offset ages by that many positions, bits that cross the far edge
// fall out of view, and the new counter is marked at offset 0. A counter at or
// below largest is accepted only if it lands inside the window and its bit is
// clear; a hit is a replay, a miss below the window is stale, and both are
// rejected. The window is empty until the first accepted counter seeds largest;
// an explicit initialized flag means counter 0 is a legal first counter, the
// WireGuard convention, not a sentinel.
//
// Zero-heap and caller-owned (BE-WIRE-01): the caller declares a ReplayWindow on
// its own frame and the structure never allocates. The bitmap is fixed at 128
// bytes; a counter past the window edge is rejected in O(1), an advance is O(16
// words). This module is a state machine over authenticated counters; it is
// transport, not parser, so it is outside the M5 line budget (D-018). A rekey
// (BE-TR-02) starts a fresh session key, so the caller swaps in a fresh
// ReplayWindow rather than resetting fields in place: counters do not carry over
// across keys.

const std = @import("std");

// BE-TR-03 floor: the window MUST be at least 1024 counters wide.
pub const WINDOW_BITS: usize = 1024;

// A 64-bit machine word; the bitmap is an array of these.
pub const WORD_BITS: usize = 64;
pub const WINDOW_WORDS: usize = WINDOW_BITS / WORD_BITS; // 16

pub const ReplayWindow = struct {
    // window[w] bit b set means counter (largest - (w*64 + b)) has been seen.
    window: [WINDOW_WORDS]u64 = std.mem.zeroes([WINDOW_WORDS]u64),
    largest: u64 = 0,
    initialized: bool = false,

    pub fn init() ReplayWindow {
        return .{};
    }

    // Check a counter against the window and, on accept, record it. Returns
    // true for a fresh counter inside or ahead of the window, false for a
    // replay (already seen) or a stale counter (below the window). The first
    // call seeds largest with whatever counter arrives, including 0.
    pub fn check(self: *ReplayWindow, counter: u64) bool {
        if (!self.initialized) {
            self.initialized = true;
            self.largest = counter;
            self.window[0] |= 1; // offset 0 == largest
            return true;
        }

        if (counter > self.largest) {
            // Advance: age every remembered offset by the gap to the new
            // highest, drop what falls past the far edge, mark the new top.
            const shift = counter - self.largest;
            shiftLeft(&self.window, shift);
            self.largest = counter;
            self.window[0] |= 1; // offset 0 == new largest
            return true;
        }

        // counter <= largest: inside the window or below it.
        const diff = self.largest - counter;
        if (diff >= WINDOW_BITS) return false; // below the window
        const w = diff / WORD_BITS;
        const b = diff % WORD_BITS;
        const mask: u64 = @as(u64, 1) << @intCast(b);
        if ((self.window[w] & mask) != 0) return false; // already seen: replay
        self.window[w] |= mask;
        return true;
    }
};

// Shift the 1024-bit window LEFT by `shift` positions: every set bit ages by
// `shift` offsets (toward the far edge of the window). A shift at or beyond the
// window width clears the bitmap entirely. The process runs high word to low so
// each destination word is written before its source is read.
fn shiftLeft(win: *[WINDOW_WORDS]u64, shift: u64) void {
    if (shift >= WINDOW_BITS) {
        win.* = std.mem.zeroes([WINDOW_WORDS]u64);
        return;
    }
    const word_shift: usize = @intCast(shift / WORD_BITS);
    const bit_shift: usize = @intCast(shift % WORD_BITS);

    var w: usize = WINDOW_WORDS;
    while (w > 0) {
        w -= 1;
        var v: u64 = 0;
        if (bit_shift == 0) {
            if (w >= word_shift) v = win[w - word_shift];
        } else {
            const lo: u6 = @intCast(bit_shift);
            const carry: u6 = @intCast(WORD_BITS - bit_shift);
            if (w >= word_shift) v = win[w - word_shift] << lo;
            if (w >= word_shift + 1) v |= win[w - word_shift - 1] >> carry;
        }
        win[w] = v;
    }
}
