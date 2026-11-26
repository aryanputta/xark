#!/usr/bin/env python3
"""Screen one-factor B2 candidates with the competitive benchmark runner."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def load(path):
    return json.loads(path.read_text())


def write(path, data):
    path.write_text(json.dumps(data, indent=2) + "\n")


def ratios(report, workload, metric):
    result = []
    for pair in report["comparisons"]:
        if pair["workload"] != workload:
            continue
        stats = pair["arm_statistics"]
        baseline, candidate = (
            stats[backend][metric] for backend in ("xark", "xark-candidate")
        )
        result.append(
            {
                "pair": pair["pair"],
                "p50": candidate["p50_ns"] / baseline["p50_ns"],
                "p95": (
                    candidate["p95_ns"] / baseline["p95_ns"]
                    if baseline["p95_ns"] and candidate["p95_ns"]
                    else None
                ),
            }
        )
    return result


def run_candidate(args, config, stage, workloads, case_dir):
    output = case_dir / stage
    command = [
        sys.executable,
        str(args.runner.resolve(strict=True)),
        "--config",
        str(config),
        "--output",
        str(output),
        "--competitor",
        "xark",
        "--threads",
        str(args.threads),
        "--pairs",
        str(args.pairs),
        "--samples",
        str(args.samples),
        "--warmups",
        str(args.warmups),
        "--timeout",
        str(args.timeout),
    ]
    for workload in workloads:
        command.extend(("--workload", workload))
    if stage == "b2":
        command.extend(("--xark-query", "b2"))
    command.extend(("--smoke",) if args.smoke else ("--strict-contention",))
    with (case_dir / f"{stage}.log").open("w") as log:
        result = subprocess.run(
            command, stdout=log, stderr=subprocess.STDOUT, check=False
        )
    report_path = output / "report.json"
    return {
        "argv": command,
        "exit": result.returncode,
        "report": str(report_path) if report_path.is_file() else None,
        "log": str(case_dir / f"{stage}.log"),
    }


def peak_memory(report):
    samples = {"xark": [], "xark-candidate": []}
    for step in report["steps"]:
        for backend in samples:
            if step["log"].endswith(f"-{backend}.log"):
                rss = step.get("contention", {}).get("sampled_peak_rss_kib")
                if rss is None:
                    return None
                samples[backend].append(rss)
    if not all(samples.values()):
        return None
    return max(samples["xark-candidate"]) / max(samples["xark"])


def stable(pairs, limit):
    return bool(pairs) and all(
        row["p50"] <= limit and row["p95"] is not None and row["p95"] <= 1.02
        for row in pairs
    )


def run(args):
    definition = load(args.plan)
    if not definition:
        raise ValueError("the plan needs at least one candidate")
    args.output = args.output.resolve()
    args.output.mkdir(mode=0o700)
    results = []
    for case in definition:
        case_id = case["name"]
        if not case_id.isascii() or not case_id.replace("-", "").isalnum():
            raise ValueError(
                "candidate names must use ASCII letters, digits, or hyphens"
            )
        if not isinstance(case["factor"], str) or not case["factor"].strip():
            raise ValueError(f"{case_id} needs a single changed factor")
        config = (args.plan.parent / case["config"]).resolve(strict=True)
        parameters = load(config)
        candidate = parameters["candidate"]
        if len(candidate.get("environment", {})) > 1:
            raise ValueError(f"{case_id} must vary at most one environment setting")
        config_paths = parameters["binaries"]
        same_binary = (config.parent / config_paths["bench"]).resolve() == (
            config.parent / candidate["binary"]
        ).resolve()
        if same_binary and not candidate.get("environment"):
            raise ValueError(f"{case_id} must have a distinct candidate")
        if not same_binary and candidate.get("environment"):
            raise ValueError(f"{case_id} must vary either the binary or one setting")
        case_dir = args.output / case_id
        case_dir.mkdir()
        record = {
            "name": case_id,
            "factor": case["factor"],
            "input_config": str(config),
            "config_sha256": hashlib.sha256(config.read_bytes()).hexdigest(),
            "candidate": candidate,
            "b2": run_candidate(args, config, "b2", [args.tune_workload], case_dir),
            "decision": "no_verified_report",
        }
        results.append(record)
        query_report = record["b2"]["report"]
        if query_report:
            query = load(Path(query_report))
            query_ratios = ratios(query, args.tune_workload, "b2")
            record["b2_ratios"] = query_ratios
            needs_proof = args.smoke or (
                query["performance_eligible"] and stable(query_ratios, 1 - args.b2_gate)
            )
            record["decision"] = "b2_gate_not_met"
            if needs_proof:
                withheld = next(
                    w for w in ("escrow", "withdrawal") if w != args.tune_workload
                )
                record["proof"] = run_candidate(
                    args, config, "proof", [args.tune_workload, withheld], case_dir
                )
                record["decision"] = "no_verified_proof_report"
                proof_report = record["proof"]["report"]
                if proof_report:
                    proof = load(Path(proof_report))
                    tuned = ratios(proof, args.tune_workload, "proof")
                    holdout = ratios(proof, withheld, "proof")
                    memory = peak_memory(proof)
                    record.update(
                        proof_ratios=tuned,
                        holdout_workload=withheld,
                        holdout_ratios=holdout,
                        peak_rss_ratio=memory,
                        decision="proof_gate_not_met",
                    )
                    if args.smoke:
                        record["decision"] = "verified_smoke"
                    elif (
                        proof["performance_eligible"]
                        and stable(tuned, 1 - args.proof_gate)
                        and stable(holdout, 1.02)
                        and memory is not None
                        and memory <= 1.05
                    ):
                        record["decision"] = "passed_screen"
        ranked = sorted(
            (row for row in results if row["decision"] == "passed_screen"),
            key=lambda row: (
                max(pair["p50"] for pair in row["proof_ratios"]),
                max(pair["p50"] for pair in row["b2_ratios"]),
                row["peak_rss_ratio"],
            ),
        )
        write(
            args.output / "decisions.json",
            {
                "candidates": results,
                "ranked": [row["name"] for row in ranked],
                "winner": ranked[0]["name"] if ranked else None,
            },
        )
    return all(
        row["decision"] in {"verified_smoke", "passed_screen"} for row in results
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runner", required=True, type=Path)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--tune-workload", choices=("withdrawal", "escrow"), default="withdrawal"
    )
    parser.add_argument("--threads", type=int, default=2)
    parser.add_argument("--samples", type=int, default=100)
    parser.add_argument("--warmups", type=int, default=3)
    parser.add_argument("--pairs", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=600)
    parser.add_argument("--b2-gate", type=float, default=0.20)
    parser.add_argument("--proof-gate", type=float, default=0.10)
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    try:
        if not (0 < args.b2_gate < 1 and 0 < args.proof_gate < 1):
            raise ValueError("promotion thresholds must be between zero and one")
        return 0 if run(args) else 1
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"tuning: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
