#!/usr/bin/env python3
"""Conformance runner: project fixtures, run TLC, verify classifications.

Usage: run-conformance.py <tla2tools.jar> [fixtures_dir] [out_dir]

For each fixture:
  1. Run project.py to generate a trace-constrained TLA+ module.
  2. If PROJECTED, run TLC with the Bolina base invariants + NotAccepted.
  3. The case is ACCEPTED when TLC reaches the self-loop (NotAccepted violated),
     NONCONFORMANT when TLC deadlocks at an expected action, and whatever the
     projector returned for INVALID_TRACE / OUT_OF_SCOPE / INSTRUMENTATION_ERROR.
  4. Compare actual classification with the fixture's "expect" field.
"""

import json
import os
import subprocess
import sys
import tempfile

# The invariants every trace module inherits from Bolina.
TRACE_INVARIANTS = [
    "TypeOK",
    "CommitBeforeEffect",
    "AtMostOneActionEffectAttempt",
    "ConsumedSurvivesRestartWhileAcceptable",
    "NoUnauthorizedExecuting",
    "VerificationLockHeld",
    "RestartClearsPending",
    "ResourceExclusive",
    "ExecutionEstablishedAtEffectStart",
    "DurableWitnessNeverAuthorizesEffect",
    "NoRecoveryPublicationAfterDurableTombstone",
    "RecoveryNeverRetriesActionEffect",
    "NoCommitBeforeCheck10",
    # The trace acceptance marker: TLC violates this exactly when every
    # event was admitted, which is the success signal.
    "NotAccepted",
    "RevokedGrantsNeverExecute",
]


def write_trace_cfg(module_name, out_path):
    """Write a TLC config for a trace module."""
    lines = ["SPECIFICATION TraceSpec"]
    lines.append("")
    lines.append("CHECK_DEADLOCK FALSE")
    lines.append("")
    for inv in TRACE_INVARIANTS:
        lines.append(f"INVARIANT {inv}")
    lines.append("")
    with open(out_path, "w") as f:
        f.write("\n".join(lines) + "\n")


def run_project(fixture_path, out_dir):
    """Run project.py. Returns (classification, detail, module_name)."""
    result = subprocess.run(
        [sys.executable, os.path.join(os.path.dirname(__file__), "project.py"),
         fixture_path, out_dir],
        capture_output=True, text=True
    )
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return "ERROR", result.stdout + result.stderr, None
    classification = data.get("classification", "ERROR")
    detail = data.get("detail", "")
    module = data.get("module")
    return classification, detail, module


def run_tlc(tla_jar, spec_path, cfg_path, out_dir):
    """Run TLC on a spec. Returns (exit_code, log_text)."""
    result = subprocess.run(
        ["java", "-Xmx6g", "-XX:+UseParallelGC",
         "-cp", tla_jar, "tlc2.TLC",
         "-workers", "auto",
         "-cleanup",
         "-config", cfg_path,
         spec_path],
        capture_output=True, text=True, timeout=300,
        cwd=out_dir
    )
    return result.returncode, result.stdout + result.stderr


def classify_tlc(log_text):
    """Classify TLC output. Returns ACCEPTED or NONCONFORMANT."""
    if "NotAccepted is violated" in log_text:
        return "ACCEPTED"
    if "Deadlock" in log_text or "is violated" in log_text:
        return "NONCONFORMANT"
    if "Model checking completed" in log_text and "No error" in log_text:
        # No error means all invariants held, including NotAccepted.
        # That means the trace was NOT fully consumed (NotAccepted stayed TRUE).
        return "NONCONFORMANT"
    return "ERROR"


def main():
    if len(sys.argv) < 2:
        print("usage: run-conformance.py <tla2tools.jar> [fixtures_dir] [out_dir]", file=sys.stderr)
        return 2
    tla_jar = sys.argv[1]
    fixtures_dir = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(__file__), "fixtures")
    out_dir = sys.argv[3] if len(sys.argv) > 3 else tempfile.mkdtemp(prefix="conformance_")

    os.makedirs(out_dir, exist_ok=True)

    fixtures = sorted(f for f in os.listdir(fixtures_dir) if f.endswith(".json"))
    if not fixtures:
        print("No fixtures found in", fixtures_dir, file=sys.stderr)
        return 1

    results = []
    failures = []

    for fname in fixtures:
        fixture_path = os.path.join(fixtures_dir, fname)
        with open(fixture_path) as f:
            fixture = json.load(f)
        case = fixture.get("case", fname)
        expect = fixture.get("expect", "UNKNOWN")

        # Step 1: project
        case_out = os.path.join(out_dir, case)
        os.makedirs(case_out, exist_ok=True)
        classification, detail, module_name = run_project(fixture_path, case_out)

        # Step 2: if projected, run TLC
        if classification == "PROJECTED" and module_name:
            spec_path = os.path.join(case_out, module_name + ".tla")
            cfg_path = os.path.join(case_out, module_name + ".cfg")
            write_trace_cfg(module_name, cfg_path)
            exit_code, log_text = run_tlc(tla_jar, spec_path, cfg_path, case_out)
            tlc_class = classify_tlc(log_text)
            # Save the log
            with open(os.path.join(case_out, "tlc.log"), "w") as f:
                f.write(log_text)
            classification = tlc_class
            detail = f"TLC exit {exit_code}"

        # Step 3: compare
        passed = classification == expect
        status = "PASS" if passed else "FAIL"
        results.append((case, expect, classification, status))
        if not passed:
            failures.append(case)

        icon = "✅" if passed else "❌"
        print(f"  {icon} {case}: expect={expect} got={classification}")

    # Summary
    print(f"\n{'=' * 60}")
    total = len(results)
    ok = total - len(failures)
    print(f"  {ok}/{total} passed")
    if failures:
        print(f"  FAILURES: {', '.join(failures)}")
        return 1
    print("  All conformance cases passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
