// dispatch.zig
//
// Phase A dispatch core (DAEMON-ESTIMATE.md phase A, ruling D-059).
// Non-surface, state over parsed values (D-018 lineage): drives the bound
// state machines over parsed envelopes, in memory, zero sockets. The daemon
// milestone's first falsification: every body_type routes to its machine
// with the right context, outcomes propagate as declared, and nothing the
// verify frames do not allow ever leaves them (BE-GRANT-03b).
//
// Post-admission by contract (D-059): envelope admission (BE-ENV-02/03,
// sequence window, cert chain) is the caller's seam and lands with the
// listener in phase B. Dispatch runs verifyEnvelope as its minimum
// structural gate, then routes body_type to its machine.
//
// Seams the daemon supplies are injected as bare function hooks (M10
// shape): execute_effect (single effect call site), cert_for_sender
// (session-state lookup), on_rejected. The consumed-grant hook (BE-GRANT-01
// stand-in) is a module check-and-set registry in phase A; the phase-B
// executor replaces it with a durable commit. Clock is caller-supplied
// now_ms (house pattern).
//
// Dispatch binds no new M1 marker: it exercises the 109 already bound.

const std = @import("std");
const channel = @import("parser/channel.zig");
const session = @import("parser/session.zig");
const intent_mod = @import("intent.zig");
const resolver_mod = @import("resolver.zig");
const verify = @import("verify.zig");

// Declared defaults (SPEC grant receipts, D-059).
pub const T_MAX_S_DEFAULT: u64 = 3600;
pub const T_RECV_S_DEFAULT: u64 = 300;

// Phase-A seam bounds (D-059): dispatch copies intent sender and action at
// admit time because intent.Entry carries neither; phase B sizes both from
// the session MTU.
pub const MAX_ACTION: usize = 512;
pub const MAX_CONSUMED: usize = 256;

pub const DispatchError = error{
    BadEnvelope, // structural verification refused
    BadBody, // body bytes do not parse for the declared body_type
    UnsupportedBody, // body_type has no phase-A route
    NoPendingIntent, // grant names no pending intent
    UnknownSender, // session seam has no cert, or sender record missing
    ActionTooLarge, // intent action exceeds the phase-A seam bound
};

pub const Outcome = enum {
    intent_admitted, // lock held, pending approval
    grant_executed, // effect callback fired once, inside verifyGrantThen
    refusal_applied, // pending intent moved to REJECTED, or dropped no-match
    utterance, // pass-through, zero state change
    control, // routing-verified; full wiring phase B
    effect, // routing-verified; full wiring phase B
};

pub const Hooks = struct {
    execute_effect: *const fn (channel.Grant) void,
    cert_for_sender: *const fn (sender: []const u8) ?session.Cert,
    on_rejected: *const fn (intent_id: []const u8) void,
};

// Consumed-grant registry (BE-GRANT-01 stand-in, D-059): check-and-set.
// First sight of a grant_id marks it consumed and returns false; replays
// return true. Module-level because the hook is a bare function pointer
// (M10 shape); phase B replaces it with the durable ledger commit.
var consumed_registry: [MAX_CONSUMED][channel.LEN_GRANT_ID]u8 = undefined;
var consumed_len: usize = 0;

fn consumedHook(grant_id: []const u8) bool {
    for (consumed_registry[0..consumed_len]) |c| {
        if (std.mem.eql(u8, &c, grant_id)) return true;
    }
    if (consumed_len < MAX_CONSUMED and grant_id.len == channel.LEN_GRANT_ID) {
        @memcpy(&consumed_registry[consumed_len], grant_id);
        consumed_len += 1;
    }
    return false;
}

pub fn resetConsumedRegistry() void {
    consumed_len = 0;
}

const SenderRecord = struct {
    intent_id: [channel.LEN_INTENT_ID]u8,
    sender: [32]u8,
    action: [MAX_ACTION]u8,
    action_len: usize,
};

pub const Dispatch = struct {
    intents: intent_mod.Table,
    resolver: resolver_mod.Resolver,
    // Executor identity (D-059): construction state, sourced from session
    // establishment in phase B.
    own_pubkey: []const u8,
    own_cert: session.Cert,
    trusted_ca_keys: []const []const u8,
    senders: [intent_mod.MAX_PENDING]SenderRecord,
    senders_len: usize,

    pub fn init(res: resolver_mod.Resolver, own_pubkey: []const u8, own_cert: session.Cert, trusted_ca_keys: []const []const u8) Dispatch {
        return .{
            .intents = intent_mod.Table.init(),
            .resolver = res,
            .own_pubkey = own_pubkey,
            .own_cert = own_cert,
            .trusted_ca_keys = trusted_ca_keys,
            .senders = undefined,
            .senders_len = 0,
        };
    }

    // dispatch (D-059): structural gate, then body_type routing. The full
    // machines run for intent, grant, and refusal; utterance passes through
    // untouched; control and effect are routing-verified only until phase B
    // gives them session and channel state.
    pub fn dispatch(self: *Dispatch, env: channel.Envelope, hooks: Hooks, now_ms: u64) (DispatchError || verify.VerifyError || resolver_mod.ResolveError || intent_mod.IntentError)!Outcome {
        verify.verifyEnvelope(env) catch return error.BadEnvelope;
        return switch (env.body_type) {
            channel.BODY_INTENT => self.dispatchIntent(env, now_ms),
            channel.BODY_GRANT => self.dispatchGrant(env, hooks, now_ms),
            channel.BODY_REFUSAL => self.dispatchRefusal(env, hooks, now_ms),
            channel.BODY_UTTERANCE => Outcome.utterance,
            channel.BODY_CONTROL => Outcome.control,
            channel.BODY_EFFECT => Outcome.effect,
            else => error.UnsupportedBody,
        };
    }

    fn dispatchIntent(self: *Dispatch, env: channel.Envelope, now_ms: u64) (DispatchError || resolver_mod.ResolveError || intent_mod.IntentError)!Outcome {
        const it = channel.parseIntent(env.body) catch return error.BadBody;
        if (it.action.len > MAX_ACTION) return error.ActionTooLarge;
        try self.resolver.resolveAndAdmit(&self.intents, it, now_ms);
        if (self.senders_len < self.senders.len and env.sender.len == 32 and it.intent_id.len == channel.LEN_INTENT_ID) {
            const rec = &self.senders[self.senders_len];
            @memcpy(rec.intent_id[0..channel.LEN_INTENT_ID], it.intent_id);
            @memcpy(rec.sender[0..32], env.sender);
            @memcpy(rec.action[0..it.action.len], it.action);
            rec.action_len = it.action.len;
            self.senders_len += 1;
        }
        return Outcome.intent_admitted;
    }

    fn senderFor(self: *const Dispatch, intent_id: [channel.LEN_INTENT_ID]u8) ?*const SenderRecord {
        for (self.senders[0..self.senders_len]) |*rec| {
            if (std.mem.eql(u8, &rec.intent_id, &intent_id)) return rec;
        }
        return null;
    }

    fn dispatchGrant(self: *Dispatch, env: channel.Envelope, hooks: Hooks, now_ms: u64) (DispatchError || verify.VerifyError || intent_mod.IntentError)!Outcome {
        const grant = channel.parseGrant(env.body) catch return error.BadBody;
        const idx = self.intents.matchForGrant(grant.intent_id) orelse return error.NoPendingIntent;
        const entry = self.intents.entries[idx];
        const rec = self.senderFor(entry.intent_id) orelse return error.UnknownSender;
        const approver_cert = hooks.cert_for_sender(env.sender) orelse return error.UnknownSender;
        // D-059 correction: the subject cert belongs to the intent sender and
        // rides the same session seam, never construction state.
        const subject_cert = hooks.cert_for_sender(&rec.sender) orelse return error.UnknownSender;
        const ctx = verify.GrantContext{
            .own_pubkey = self.own_pubkey,
            .trusted_ca_keys = self.trusted_ca_keys,
            .approver_cert = approver_cert,
            .subject_cert = subject_cert,
            .intent_sender = &rec.sender,
            .pending_intent_id = &entry.intent_id,
            .pending_resource_id = entry.resource_id[0..entry.resource_len],
            .intent_action = rec.action[0..rec.action_len],
            .now_ms = now_ms,
            .first_receipt_ms = now_ms,
            .t_max_s = T_MAX_S_DEFAULT,
            .t_recv_s = T_RECV_S_DEFAULT,
            .already_consumed = consumedHook,
        };
        try verify.verifyGrantThen(env, &grant, ctx, hooks.execute_effect);
        // Phase A ordering (D-059): the EXECUTING transition lands after a
        // successful verify frame. Dispatch is single-threaded in memory, so
        // the match-to-transition frame race BE-GRANT-03a names does not
        // exist until the phase-B listener owns the frame.
        try self.intents.beginExecuting(idx);
        return Outcome.grant_executed;
    }

    fn dispatchRefusal(self: *Dispatch, env: channel.Envelope, hooks: Hooks, now_ms: u64) (DispatchError || verify.VerifyError)!Outcome {
        const refusal = channel.parseRefusal(env.body) catch return error.BadBody;
        const approver_cert = hooks.cert_for_sender(env.sender) orelse return error.UnknownSender;
        const ctx = verify.RefusalContext{
            .trusted_ca_keys = self.trusted_ca_keys,
            .approver_cert = approver_cert,
            .now_ms = now_ms,
            .intent_table = &self.intents,
        };
        try verify.verifyRefusalThen(env, refusal, ctx, hooks.on_rejected);
        return Outcome.refusal_applied;
    }
};
