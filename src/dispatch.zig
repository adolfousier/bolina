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
// (session-state lookup), on_rejected. The consumed-grant hook (BE-GRANT-01)
// is the durable ledger commit of src/grant_ledger.zig (D-061/D-062): the
// grant_id is committed durably before the effect fires, tombstoned after it
// returns. Clock is caller-supplied now_ms (house pattern).
//
// Dispatch binds no new M1 marker: it exercises the 109 already bound.

const std = @import("std");
const channel = @import("parser/channel.zig");
const session = @import("parser/session.zig");
const intent_mod = @import("intent.zig");
const resolver_mod = @import("resolver.zig");
const verify = @import("verify.zig");
const grant_ledger = @import("grant_ledger.zig");
const grant_trace = @import("grant_trace.zig");

// Declared defaults (SPEC grant receipts, D-059).
pub const T_MAX_S_DEFAULT: u64 = 3600;
pub const T_RECV_S_DEFAULT: u64 = 300;

// Seam bounds (D-059): dispatch copies intent sender and action at admit
// time because intent.Entry carries neither; phase B sizes both from the
// session MTU.
pub const MAX_ACTION: usize = 512;

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
    effect_refused, // checks passed, commit durable, executor declined: unpublished orphan (BE-GRANT-01a, brief 9.1)
    refusal_applied, // pending intent moved to REJECTED, or dropped no-match
    utterance, // pass-through, zero state change
    control, // routing-verified; full wiring phase B
    effect, // routing-verified; full wiring phase B
};

pub const Hooks = struct {
    execute_effect: *const fn (channel.Grant) verify.EffectOutcome,
    cert_for_sender: *const fn (sender: []const u8) ?session.Cert,
    on_rejected: *const fn (intent_id: []const u8) void,
};

// Consumed-grant ledger seam (BE-GRANT-01, D-062): the D-059 in-memory
// consumed_registry stand-in replaced by the durable two-phase append log of
// src/grant_ledger.zig (D-061). Module-level because the hook is a bare
// function pointer (M10 shape). The daemon initializes the ledger exactly
// once at startup via initDurableLedger and receives the recovered orphans:
// committed-but-unpublished grants for which it publishes exactly one
// interrupted Effect each (BE-GRANT-01a) before calling tombstoneOrphan.
// Restart semantics (BE-GRANT-04): pending approvals live only in the
// in-memory intent table and are never committed here, so a restart expires
// them by construction.
var durable_ledger: ?grant_ledger.GrantLedger = null;

// Open (or create) the durable ledger at path and recover. Copies recovered
// orphans into orphan_out and returns their count; the copy is deliberate:
// Recovery borrows the ledger's internal buffer, and tombstoneOrphan mutates
// the ledger, so the caller must hold its own list while it publishes the
// interrupted Effects. ResourceExhausted if the orphan list does not fit.
pub fn initDurableLedger(io: std.Io, path: []const u8, orphan_out: []grant_ledger.OrphanGrant) grant_ledger.LedgerError!usize {
    var lg = try grant_ledger.GrantLedger.open(io, path);
    const r = try lg.recover();
    if (r.orphans.len > orphan_out.len) {
        lg.close();
        return error.ResourceExhausted;
    }
    @memcpy(orphan_out[0..r.orphans.len], r.orphans);
    durable_ledger = lg;
    return r.orphans.len;
}

pub fn closeDurableLedger() void {
    if (durable_ledger) |*lg| {
        lg.close();
        durable_ledger = null;
    }
}

// Test-only write-failure injection for the Phase B conformance pilot
// (brief section 6: crash between consume and tombstone, D-080 ruling 1's
// loud-in-evidence promise). Swaps the ledger's read-write handle for a
// read-only one opened on the same path: the next append fails (a write on
// an O_RDONLY fd is EBADF) exactly like a lost tombstone write would, while
// every later close stays valid (double-closing a real fd is a detected OS
// bug in std.Io.Threaded.closeFd, so the original handle leaks instead;
// harmless in a test process). Production never calls this.
pub fn seamBreakLedgerWrites(io: std.Io) void {
    if (durable_ledger) |*lg| {
        const dir = std.Io.Dir.cwd();
        const ro = dir.openFile(io, lg.path_buf[0..lg.path_len], .{ .mode = .read_only }) catch return;
        lg.file = ro;
    }
}

// The caller has published the interrupted Effect for an orphan
// (BE-GRANT-01a) and now tombstones it so later recoveries skip it.
pub fn tombstoneOrphan(grant_id: [channel.LEN_GRANT_ID]u8) grant_ledger.LedgerError!void {
    if (durable_ledger) |*lg| {
        try lg.markPublished(grant_id);
        if (grant_trace.enabled) grant_trace.emit(.recover_mark_published, grant_trace.NO_PC, &grant_id, 0);
    }
}

// Check 11 hook (D-062): durably commit-before-effect. Returns true when the
// grant_id is ALREADY consumed (replay). No initialized ledger refuses every
// grant: without the durable commit the effect must not run (fail-safe,
// BE-GRANT-01). A failed commit (resource exhaustion) likewise refuses: an
// uncommitted grant is unspent, so the effect does not run; the refusal
// surfaces as AlreadyConsumed because the hook contract is a bool.
fn consumedHook(grant_id: []const u8, not_after_ms: u64, now_ms: u64) bool {
    var lg = &(durable_ledger orelse return true);
    if (grant_id.len != channel.LEN_GRANT_ID) return true;
    var gid: [channel.LEN_GRANT_ID]u8 = undefined;
    @memcpy(&gid, grant_id[0..channel.LEN_GRANT_ID]);
    if (lg.isConsumed(gid)) return true;
    lg.commitConsumed(gid, not_after_ms, now_ms) catch return true;
    return false;
}

// Checks 3/4 hook (F4 / BE-REV-02): consult the durable revocation set at the
// grant checkpoint, where capability turns into effect. The principle is
// "revoked as of this use, not of cache fill" (verify.zig:454): the grant path
// is the use, so revocation is re-checked here, not just at mesh establish.
// Returns true when the sig_pubkey is durably revoked. No initialized ledger
// refuses every grant (fail-safe): without the revocation set loaded, no grant
// may turn into an effect.
fn isRevokedHook(sig_pubkey: []const u8) bool {
    var lg = &(durable_ledger orelse return true);
    if (sig_pubkey.len != grant_ledger.SIG_PUBKEY_LEN) return true;
    var key: [grant_ledger.SIG_PUBKEY_LEN]u8 = undefined;
    @memcpy(&key, sig_pubkey[0..grant_ledger.SIG_PUBKEY_LEN]);
    return lg.isRevoked(key);
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
        self.resolver.resolveAndAdmit(&self.intents, it, now_ms) catch |e| {
            if (grant_trace.enabled) {
                if (e == error.ResourceHeld) {
                    // The CANONICAL resource, not the wire spelling: two
                    // aliases resolve to one resource, and exclusivity is a
                    // property of the canonical one. Resolution already
                    // succeeded here (the refusal was the lock, not the
                    // name), so the fallback is unreachable in practice.
                    const canon = self.resolver.resolve(it.resource_id) catch it.resource_id;
                    grant_trace.emit2(.reject_resource_conflict, grant_trace.NO_PC, it.intent_id, canon, now_ms);
                }
            }
            return e;
        };
        if (grant_trace.enabled) {
            const canon = self.resolver.resolve(it.resource_id) catch it.resource_id;
            grant_trace.emit2(.receive_intent, grant_trace.NO_PC, it.intent_id, canon, now_ms);
        }
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
            .is_revoked = isRevokedHook,
        };
        const effect_outcome = try verify.verifyGrantThen(env, &grant, ctx, hooks.execute_effect);
        // Brief 9.1: the outcome is the publication boundary's evidence
        // source. A refused effect never reaches markPublished: publishing
        // a grant whose effect never fired would be false evidence under
        // the D-067 correspondence rule. The commit row from check 11
        // stands, so the spent capability refuses any replay.
        if (effect_outcome == .refused) return Outcome.effect_refused;
        // Brief section 6: the effect outcome is the publication attempt's
        // evidence source. Reaching this line means the outcome is .fired.
        if (grant_trace.enabled) grant_trace.emit(.publish_outcome, grant_trace.NO_PC, grant.grant_id, now_ms);
        // BE-GRANT-01a: the effect returned, so the grant is published. The
        // tombstone keeps the next recovery from re-emitting it as an orphan.
        // A failed tombstone write is fail-safe, not a dispatch failure: the
        // grant stays consumed, and recovery re-emits interrupted for it
        // (at-least-once), so an executed effect is never reported as an error.
        // D-080 ruling 1: the failure stays silent in control flow but loud
        // in evidence (mark_published_failed), never projected as success.
        if (durable_ledger) |*lg| {
            if (grant.grant_id.len == channel.LEN_GRANT_ID) {
                var gid: [channel.LEN_GRANT_ID]u8 = undefined;
                @memcpy(&gid, grant.grant_id[0..channel.LEN_GRANT_ID]);
                lg.markPublished(gid) catch {
                    if (grant_trace.enabled) grant_trace.emit(.mark_published_failed, grant_trace.NO_PC, grant.grant_id, now_ms);
                };
            }
        }
        // Phase A ordering (D-059): the EXECUTING transition lands after a
        // successful verify frame. Dispatch is single-threaded in memory, so
        // the match-to-transition frame race BE-GRANT-03a names does not
        // exist until the phase-B listener owns the frame.
        try self.intents.beginExecuting(idx);
        if (grant_trace.enabled) grant_trace.emit(.record_executing_witness, grant_trace.NO_PC, grant.grant_id, now_ms);
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
