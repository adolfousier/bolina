# G2 interop receipt - closed and independently verified

Gate G2 of D-092 (second implementation, live transport) is CLOSED. This
directory snapshots the closing evidence; the canonical source is the
lastro repo at `evidence/g2/` (commit `ad26855`), which also holds the
full run logs and README.

| File | What it is |
|---|---|
| `g2.receipt` | Bolina Span signed by runner-g3 (`a1c71dab7e4c24a3`) over the conformant interop run |
| `g2-observed.log` | The exact captured stream the digest covers |

## Verification record (independent, Bolina side)

```
lastro verify --cert ci/runner-g3/cert.bin \
  --ca ci/ca/ca/ca0.pub --ca ci/ca/ca/ca1.pub g2.receipt
-> VERIFIED
resource: bol:a1c71dab7e4c24a3/git/bolina/9447ca86cec2.../check/g2-interop-live
digest:   de91a82a1a43c585fa02ff2744f7ab0e8422344eeacdbfdf803e75dfd88fe39f
chain:    clock-free (BE-HIST-01), observed inside cert window
```

Digest-to-stream binding: BLAKE2s-256 of `g2-observed.log` equals the
receipt digest byte-exactly. The stream shows both sides spec-conformant
(SPEC 4.1a layout after fix `e4fd0d4`: daemon slot `0x00000000` at offset
4, initiator echo `0x51530001`), mutual BE-TR-01 binding, stage C intent
admitted (`pending`), exit-status 0.

Full story: D-095 in `docs/DECISION-LOG.md` (Amendment 2).
