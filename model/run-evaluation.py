#!/usr/bin/env python3
"""Run the finite Bolina witness and single-mutant discrimination suite."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


SOURCE_COMMIT = "492f0e31009bcb905e309de5572a2d25dee793bf"
JAR_PATH = Path("/home/vrondelli/.local/share/tlaplus/1.7.4/tla2tools.jar")
JAR_SHA256 = "936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"
WRAPPER_PATH = Path("/home/vrondelli/.local/bin/tlc")
WRAPPER_SHA256 = "847f9baf4a43ada83da03341404ecbe3b9575ba97156efae70c28b9102f17ff6"
BASE_MODEL_SHA256 = "be22398c015da5601f30b7658b207ad262f557d6fffdc7189dae13eba8aacbbf"

CASES = (
    ("W01", "witness", "W01NotReached", "FinishExecuted", "Spec"),
    ("W02", "witness", "W02NotReached", "ObserveIndependentResources", "Spec"),
    ("W03", "witness", "W03NotReached", "RejectResourceConflict", "Spec"),
    ("W04", "witness", "W04NotReached", "Restart", "Spec"),
    ("W05", "witness", "W05NotReached", "RecoverPublishInterrupted", "Spec"),
    ("W06", "witness", "W06NotReached", "ExpirePending", "Spec"),
    ("M01", "mutant", "CommitBeforeEffect", "M01EffectBeforeConsume", "SpecM01"),
    ("M02", "mutant", "AtMostOneActionEffectAttempt", "M02DuplicateEffect", "SpecM02"),
    ("M03", "mutant", "NoUnauthorizedExecuting", "M03UnauthorizedExecuting", "SpecM03"),
    ("M04", "mutant", "RestartClearsPending", "M04RehydratePending", "SpecM04"),
    ("M05", "mutant", "VerificationLockHeld", "M05ReleaseVerificationLock", "SpecM05"),
    ("M06", "mutant", "ExecutionEstablishedAtEffectStart", "M06EffectWithoutExecutionEstablishment", "SpecM06"),
    ("M07", "mutant", "NoRecoveryPublicationAfterDurableTombstone", "M07RecoveryAfterTombstone", "SpecM07"),
    ("M08", "mutant", "RecoveryNeverRetriesActionEffect", "M08RecoveryRetriesEffect", "SpecM08"),
    ("M09", "mutant", "NoCommitBeforeCheck10", "M09CommitBeforeCheck10", "SpecM09"),
    ("M10", "mutant", "ConsumedSurvivesRestartWhileAcceptable", "LEGACY_TRUNCATE_MUTANT", "SpecM10"),
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def exact_ref(root: Path, path: Path) -> dict[str, object]:
    data = path.read_bytes()
    try:
        rendered = path.resolve().relative_to(root).as_posix()
    except ValueError:
        rendered = path.resolve().as_posix()
    return {"path": rendered, "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def parse_state_space(text: str) -> dict[str, int | None]:
    counts = re.search(
        r"(\d+) states generated, (\d+) distinct states found, (\d+) states left on queue",
        text,
    )
    trace_states = [int(value) for value in re.findall(r"^State (\d+):", text, re.MULTILINE)]
    return {
        "generated": int(counts.group(1)) if counts else None,
        "distinct": int(counts.group(2)) if counts else None,
        "queue_remaining": int(counts.group(3)) if counts else None,
        "trace_depth": max(trace_states) if trace_states else None,
    }


def validate_material(module_path: Path, runner_path: Path, evaluation_dir: Path) -> None:
    expected_configs = {f"{case[0]}.cfg" for case in CASES}
    actual_configs = {path.name for path in evaluation_dir.glob("*.cfg")}
    if actual_configs != expected_configs:
        raise RuntimeError(
            f"evaluation config inventory drift: expected {sorted(expected_configs)}, got {sorted(actual_configs)}"
        )
    for path in (module_path, runner_path, *(evaluation_dir / name for name in sorted(expected_configs))):
        data = path.read_bytes()
        if not data.endswith(b"\n"):
            raise RuntimeError(f"missing final newline: {path}")
        if any(line.endswith((b" ", b"\t")) for line in data.splitlines()):
            raise RuntimeError(f"trailing whitespace: {path}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--model-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=300)
    args = parser.parse_args()

    root = Path(args.repo_root).resolve()
    model_dir = (root / args.model_dir).resolve()
    output_dir = (root / args.output_dir).resolve()
    receipt_path = (root / args.receipt).resolve()
    module_path = model_dir / "BolinaEvaluation.tla"
    base_model_path = model_dir / "Bolina.tla"
    runner_path = Path(__file__).resolve()

    if sha256(base_model_path) != BASE_MODEL_SHA256:
        raise RuntimeError("admitted base-model identity drift")
    validate_material(module_path, runner_path, model_dir / "evaluation")

    if sha256(JAR_PATH) != JAR_SHA256:
        raise RuntimeError("TLA+ jar identity drift")
    if sha256(WRAPPER_PATH) != WRAPPER_SHA256:
        raise RuntimeError("TLC wrapper identity drift")
    resolved_tlc = shutil.which("tlc")
    if resolved_tlc is None or Path(resolved_tlc).resolve() != WRAPPER_PATH.resolve():
        raise RuntimeError("resolved TLC wrapper is not the admitted wrapper")

    output_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, object]] = []
    for case_id, kind, expected_invariant, expected_marker, specification in CASES:
        config_path = model_dir / "evaluation" / f"{case_id}.cfg"
        command = [
            str(WRAPPER_PATH),
            "-workers", "1",
            "-cleanup",
            "-coverage", "1",
            "-config", f"evaluation/{case_id}.cfg",
            "BolinaEvaluation.tla",
        ]
        completed = subprocess.run(
            command,
            cwd=model_dir,
            check=False,
            capture_output=True,
            timeout=args.timeout_seconds,
        )
        log_data = completed.stdout + completed.stderr
        log_path = output_dir / f"{case_id}.log"
        atomic_write(log_path, log_data)
        text = log_data.decode("utf-8", errors="replace")
        violations = re.findall(r"Invariant ([A-Za-z][A-Za-z0-9_]*) is violated\.", text)
        trace_actions = re.findall(r"^State \d+: <([^>]+)>", text, re.MULTILINE)
        exact_property = violations == [expected_invariant]
        counterexample = completed.returncode != 0 and "The behavior up to this point is:" in text
        trace_marker_observed = any(expected_marker in action for action in trace_actions)
        passed = exact_property and counterexample and len(trace_actions) > 0
        results.append(
            {
                "case_id": case_id,
                "kind": kind,
                "specification": specification,
                "expected_outcome": (
                    "counterexample-to-negated-witness" if kind == "witness" else "mutant-killed-by-named-invariant"
                ),
                "actual_outcome": "expected-counterexample" if passed else "unexpected-result",
                "expected_property": expected_invariant,
                "actual_violated_properties": violations,
                "expected_trace_marker": expected_marker,
                "trace_marker_observed": trace_marker_observed,
                "trace_actions": trace_actions,
                "exit_code": completed.returncode,
                "command": {"cwd": args.model_dir, "argv": command, "timeout_seconds": args.timeout_seconds},
                "state_space": parse_state_space(text),
                "config_ref": exact_ref(root, config_path),
                "log_ref": exact_ref(root, log_path),
                "result": "pass" if passed else "block",
            }
        )

    aggregate_pass = all(case["result"] == "pass" for case in results)
    receipt = {
        "schema_version": "bolina.evaluation-receipt.v1",
        "work_pack_id": "WP-BOL-TLA-001",
        "task_id": "TASK-BOL-TLA-02",
        "swu_id": "SWU-BOL-TLA-002",
        "result": "pass" if aggregate_pass else "block",
        "source_commit": SOURCE_COMMIT,
        "claim_ceiling": "exact finite witness and single-mutant outcomes only; not a theorem or Zig conformance proof",
        "tool": {
            "tla_version": "v1.7.4",
            "tlc_banner": "TLC2 Version 2.19 of 08 August 2024",
            "jar_ref": exact_ref(root, JAR_PATH),
            "wrapper_ref": exact_ref(root, WRAPPER_PATH),
        },
        "bounds": {"intents": 2, "grants": 2, "resources": 2, "max_time": 2, "workers": 1},
        "base_model_ref": exact_ref(root, base_model_path),
        "evaluation_module_ref": exact_ref(root, module_path),
        "runner_ref": exact_ref(root, runner_path),
        "case_count": len(results),
        "witness_count": sum(case["kind"] == "witness" for case in results),
        "mutant_count": sum(case["kind"] == "mutant" for case in results),
        "cases": results,
        "m10_isolation": {
            "mutant_action": "LEGACY_TRUNCATE_MUTANT",
            "present_only_in_specification": "SpecM10",
            "corrected_base_evidence": "SWU-BOL-TLA-001 bounded-no-counterexample",
        },
        "residue": [],
    }
    atomic_write(receipt_path, (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode())
    print(json.dumps({"result": receipt["result"], "cases": len(results), "receipt": args.receipt}, sort_keys=True))
    return 0 if aggregate_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
