# Trial receipts (phase-3 dress rehearsal, 2026-08-24)

These are NOT seal receipts. They are the phase-3 trial cycle: Bolina's own gate
steps wrapped in Lastro and verified against the CI-dedicated CA, to prove the
pipeline end to end before it becomes seal procedure.

| Receipt | Step | Result |
|---------|------|--------|
| `zig-build-test.receipt` | `zig build test` | exit 0, digest `c00b64f9…` |
| `prumo-verify.receipt`   | `bash tools/prumo-verify` | exit 0, gates M1-M12, digest `d039b678…` |

Both verify clean:

```bash
lastro verify -cert ci/runner/cert.bin \
  -ca ci/ca/ca/ca0.pub -ca ci/ca/ca/ca1.pub <receipt>
```

Provenance note, stated plainly: each Span path cites `bol:<executor>/git/bolina/<sha>/...`
where `<sha>` is `7207fb000113990199a903895e2ff4dde1ec9962` — the v0.6.1 seal commit the
steps ran against. The commit that first committed these receipts is necessarily newer
(the receipts could not contain their own commit). Seal receipts produced by the real
procedure will cite their own run sha the same way.

Rotation: the signer cert lives 30 days (BE-REV-01). Gate M12 in prumo-verify fails
loudly under 7 days with the reissue command.
