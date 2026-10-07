#!/usr/bin/env python3
"""Offline Criterion CSV/Markdown report. Latency is always the whole request.

Only explicit comparisons produce ratios. Missing/failed/incompatible pairs remain
in the report. Criterion confidence intervals are within-process evidence;
independent rounds are separate rows, never pooled across CPUs.
"""
import argparse
import csv
import json
from pathlib import Path


def read_case(path):
    """Join by Criterion's full_id, not sanitized/truncated directory names."""
    run = json.loads(path.read_text())
    row = {"directory": str(path.parent), "label": run["label"], "round": run["round"],
           "cpu": run["cpu"]["logical_cpu"], "case": run["case"], "status": run["status"], "run": run}
    metadata_path = path.parent / "cases.jsonl"
    records = [json.loads(line) for line in metadata_path.read_text().splitlines()] if metadata_path.exists() else []
    metadata = [record for record in records if record["id"] == run["case"]]
    estimates = []
    for benchmark in path.parent.glob("criterion/**/new/benchmark.json"):
        if json.loads(benchmark.read_text())["full_id"] == run["case"]:
            estimates.append(benchmark.with_name("estimates.json"))
    if run["status"] != "ok":
        return row
    if len(metadata) != 1 or len(estimates) != 1:
        row["status"] = "missing_or_duplicate_evidence"
        return row
    row["metadata"] = metadata[0]
    value = json.loads(estimates[0].read_text())
    # Criterion WallTime estimates are nanoseconds, independent of console units.
    row.update(mean_ns=value["mean"]["point_estimate"], median_ns=value["median"]["point_estimate"],
               std_dev_ns=value["std_dev"]["point_estimate"],
               ci_low_ns=value["mean"]["confidence_interval"]["lower_bound"],
               ci_high_ns=value["mean"]["confidence_interval"]["upper_bound"])
    return row


def compare(base, candidate, mode):
    """Return delta=(candidate/base-1)*100; positive means slower, not faster."""
    if base is None or candidate is None:
        return "missing_pair", None
    if base["status"] != "ok" or candidate["status"] != "ok":
        return "failed_or_incomplete_pair", None
    a, b = base["run"], candidate["run"]
    if (any(a["cpu"].get(k) != b["cpu"].get(k) for k in ("logical_cpu", "host", "topology_policy", "kernel", "machine"))
            or a["round"] != b["round"] or a["policy"] != b["policy"]):
        return "cpu_round_or_policy_mismatch", None
    # lscpu also contains changing frequency readings. Compare the hardware
    # identity fields, while preserving the complete snapshot in raw evidence.
    hardware_fields = {"Model name:", "Vendor ID:", "CPU family:", "Model:", "Stepping:",
                       "Socket(s):", "Core(s) per socket:", "Thread(s) per core:"}
    def hardware(cpu):
        return {entry["field"]: entry["data"] for entry in cpu.get("lscpu", {}).get("lscpu", [])
                if entry["field"] in hardware_fields}
    if hardware(a["cpu"]) != hardware(b["cpu"]):
        return "cpu_hardware_mismatch", None
    for field in ("features", "rustc", "lock_sha256", "build_environment"):
        if a["build"].get(field) != b["build"].get(field):
            return f"{field}_mismatch", None
    x, y = base["metadata"], candidate["metadata"]
    if x["version"] != y["version"] or x["fixture_lifetime"] != y["fixture_lifetime"]:
        return "measurement_version_mismatch", None
    config_x, config_y = dict(x["configuration"]), dict(y["configuration"])
    if mode != "arithmetic":
        if (x["family"], x["engine"], x["word"], x["operation"]) != (y["family"], y["engine"], y["word"], y["operation"]):
            return "backend_mismatch", None
        if config_x.get("fft_layout_fingerprint") != config_y.get("fft_layout_fingerprint"):
            return "fft_layout_mismatch", None
        if mode == "algorithm":
            # Explicit algorithm comparisons may vary BR mapping or MVB method,
            # but never dimensions, decomposition, noise, encodings or outputs.
            for key in ("blind_rotation", "path"):
                config_x.pop(key, None)
                config_y.pop(key, None)
        if config_x != config_y:
            return "parameters_or_workload_mismatch", None
        if mode == "revision" and base["case"] != candidate["case"]:
            return "case_mismatch", None
    if mode == "arithmetic":
        # Explicit cost comparisons still require the same operation and result
        # count. All remaining unequal fields are exposed in the comparison CSV.
        if x["operation"] != y["operation"] or config_x.get("outputs") != config_y.get("outputs"):
            return "operation_or_output_mismatch", None
        status = "arithmetic_cost_only"
    else:
        status = "matched"
    if any(m.get("fft_plan", "not applicable") != "not applicable" for m in (x, y)):
        status += "; fft_algorithm_unobserved"
    if a["build"]["executables"][a["target"]]["sha256"] == b["build"]["executables"][b["target"]]["sha256"]:
        status += "; same_executable"
    return status, (candidate["mean_ns"] / base["mean_ns"] - 1) * 100


def pairs(rows, baseline, candidate, ids, mode):
    """Missing and duplicate rounds are errors in pairing, not removable outliers."""
    left = [r for r in rows if r["label"] == baseline and (not ids or r["case"] == ids[0])]
    right = [r for r in rows if r["label"] == candidate and (not ids or r["case"] == ids[1])]
    def key(row):
        return row["cpu"], row["round"], "explicit" if ids else row["case"]
    keys = sorted({key(row) for row in left + right})
    for k in keys:
        a = [r for r in left if key(r) == k]
        b = [r for r in right if key(r) == k]
        status, delta = ("duplicate_pair", None) if len(a) > 1 or len(b) > 1 else compare(a[0] if a else None, b[0] if b else None, mode)
        unequal = []
        if len(a) == len(b) == 1 and "metadata" in a[0] and "metadata" in b[0]:
            x, y = a[0]["metadata"]["configuration"], b[0]["metadata"]["configuration"]
            unequal = sorted(k for k in x.keys() | y.keys() if x.get(k) != y.get(k))
        yield {"cpu": k[0], "round": k[1], "baseline": a[0]["case"] if a else "missing",
               "candidate": b[0]["case"] if b else "missing", "status": status,
               "change_percent": delta, "unequal_fields": ",".join(unequal)}


def export(rows, output, comparisons):
    output.mkdir(parents=True, exist_ok=True)
    columns = ["label", "cpu", "round", "case", "status", "mean_ns", "median_ns", "std_dev_ns", "ci_low_ns", "ci_high_ns", "directory"]
    with (output / "requests.csv").open("w", newline="") as file:
        writer = csv.DictWriter(file, columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    lines = ["# TFHE measurement report", "", "Whole-request latency; each row is one independent process. Security and DFR are unassessed.", "",
             "Within-process CI/standard deviation do not measure between-process reproducibility. CPU IDs and rounds are kept separate.", "",
             "| Label | CPU | Round | Case | Mean (ms) | Median (ms) | SD (ms) | Status |",
             "|---|---:|---:|---|---:|---:|---:|---|"]
    for row in rows:
        numbers = [f'{row[k] / 1e6:.6f}' if k in row else "—" for k in ("mean_ns", "median_ns", "std_dev_ns")]
        lines.append(f'| {row["label"]} | {row["cpu"]} | {row["round"]} | {row["case"]} | ' + " | ".join(numbers) + f' | {row["status"]} |')
    if comparisons:
        with (output / "pairs.csv").open("w", newline="") as file:
            writer = csv.DictWriter(file, list(comparisons[0]))
            writer.writeheader()
            writer.writerows(comparisons)
        lines += ["", "## Explicit paired comparison", "", "Positive change means slower. `same_executable` means the binary did not change; any difference is repeated-run variation or an explicitly selected different workload.", "",
                  "| CPU | Round | Change (%) | Status | Unequal configuration fields |", "|---:|---:|---:|---|---|"]
        for pair in comparisons:
            delta = "—" if pair["change_percent"] is None else f'{pair["change_percent"]:+.2f}'
            lines.append(f'| {pair["cpu"]} | {pair["round"]} | {delta} | {pair["status"]} | {pair["unequal_fields"]} |')
    lines += ["", "Raw evidence and Criterion HTML remain in each `directory` listed in requests.csv. Private FFT algorithm choices are not exposed by the current table API; equal permutation fingerprints do not prove equal plans."]
    (output / "report.md").write_text("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", type=Path, nargs="+")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline-label")
    parser.add_argument("--candidate-label")
    parser.add_argument("--pair", nargs=2, metavar=("BASE_ID", "CANDIDATE_ID"))
    parser.add_argument("--comparison", choices=["revision", "algorithm", "arithmetic"], default="revision")
    args = parser.parse_args()
    if bool(args.baseline_label) != bool(args.candidate_label) or (args.pair and not args.baseline_label):
        parser.error("comparisons require both labels")
    paths = sorted({p.resolve() for root in args.inputs for p in root.rglob("run.json")})
    rows = [read_case(path) for path in paths]
    if not rows:
        parser.error("no run.json evidence found")
    comparisons = list(pairs(rows, args.baseline_label, args.candidate_label, args.pair, args.comparison)) if args.baseline_label else []
    export(rows, args.output, comparisons)
    print(args.output / "report.md")


if __name__ == "__main__":
    main()
