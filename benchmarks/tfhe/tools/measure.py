#!/usr/bin/env python3
"""Run common workloads directly, or freeze binaries for repeatable measurements.

quick selects a small u64 workload; build/run retain explicit measurement evidence.
Uses only Python's standard library. No sampling overlaps compilation.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import tarfile
import uuid

ROOT = Path(__file__).resolve().parents[3]
PACKAGE = "primus_tfhe_benchmarks"
BACKENDS = ("glwe-ntt", "glwe-fourier", "ntru-ntt", "ntru-fourier")

# One named operation selects a bounded comparison, not the entire target matrix.
# Criterion still owns setup and timing; these are only target/filter shortcuts.
QUICK_CASES = {
    "pbs": ("pbs", r"^pbs/binary/shortint_2_2/(KeyswitchBootstrap/)?complete/.*/u64$"),
    "sparse": ("sparse_pbs", r"^sparse_pbs/.*/u64$"),
    "cbs": ("cbs", r"^cbs/(classic|sparse)/(KeyswitchBootstrap/)?complete/.*/u64$"),
    "one-hot": ("cbs", r"^cbs/one_hot/.*/u64$"),
    "mvb": ("mvb", r"^mvb/.*/D8_k3/.*/u64$"),
    "lut": ("high_precision_lut", r"^high_precision_lut/(classic|sparse)/c8_d5_o8/evaluate/.*/u64$"),
    "lut-create": ("high_precision_lut", r"^high_precision_lut/classic/c8_d5_o8/create_lut_and_drop/.*/u64$"),
}


def quick_command(args):
    """Resolve backend features and workload together, rejecting unsupported pairs."""
    ntru_only = args.operation in ("one-hot", "lut", "lut-create")
    supported = ("ntru-ntt", "ntru-fourier") if ntru_only else BACKENDS
    if args.backend and args.backend not in supported:
        raise ValueError(f"{args.operation} supports: {', '.join(supported)}")
    features = [args.backend] if args.backend else list(supported)
    if any(backend.endswith("fourier") for backend in features):
        features.append(args.fft or "rustfft")
    elif args.fft:
        raise ValueError("--fft requires a Fourier backend")
    target, pattern = QUICK_CASES[args.operation]
    if target == "high_precision_lut":
        features.append("lut")
    if args.simd:
        features.append("simd")
    cargo = ["cargo", "+nightly"] if args.simd else ["cargo"]
    invocation = cargo + ["bench", "-p", PACKAGE, "--bench", target,
                          "--features", ",".join(features), "--", pattern]
    if args.list:
        invocation.append("--list")
    elif args.test:
        invocation.append("--test")
    return invocation


def quick(args):
    """Compile once, then run selected backends serially in one Criterion process."""
    invocation = quick_command(args)
    print(shlex.join(invocation), flush=True)
    raise SystemExit(subprocess.run(invocation, cwd=ROOT).returncode)


def command(args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def digest(path):
    return hashlib.file_digest(path.open("rb"), "sha256").hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def sources():
    """Fingerprint tracked and untracked sources, excluding ignored local evidence."""
    names = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=ROOT
    ).split(b"\0")
    files = {os.fsdecode(name): digest(ROOT / os.fsdecode(name))
             for name in names if name and (ROOT / os.fsdecode(name)).is_file()}
    fingerprint = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()
    return fingerprint, files


def build(args):
    """Resolve executables from Cargo JSON, never from a filename glob or mtime."""
    identity, files = sources()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    cargo = ["cargo"] + ([f"+{args.toolchain}"] if args.toolchain else [])
    feature_key = hashlib.sha256(args.features.encode()).hexdigest()[:12]
    target = ROOT / "target/benchmark-build" / identity[:16] / feature_key
    invocation = cargo + ["bench", "-p", PACKAGE, "--no-run", "--features", args.features,
                          "--target-dir", str(target), "--message-format=json"]
    for name in args.target:
        invocation += ["--bench", name]
    with (output / "cargo.jsonl").open("w") as log, (output / "build.log").open("w") as errors:
        subprocess.run(invocation, cwd=ROOT, stdout=log, stderr=errors, check=True)
    if sources()[0] != identity:
        raise RuntimeError("sources changed during compilation; build a fresh snapshot")
    executables = {}
    for line in (output / "cargo.jsonl").read_text().splitlines():
        artifact = json.loads(line)
        if (artifact.get("reason") == "compiler-artifact" and artifact.get("executable")
                and artifact["target"]["name"] in args.target
                and "bench" in artifact["target"]["kind"]):
            name = artifact["target"]["name"]
            frozen = output / name
            shutil.copy2(artifact["executable"], frozen)
            executables[name] = {"file": name, "sha256": digest(frozen), "features": artifact["features"]}
    if set(executables) != set(args.target):
        raise RuntimeError("Cargo did not produce every requested target; check required features")
    (output / "source.patch").write_text(command(["git", "diff", "HEAD", "--binary"]))
    untracked = subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard", "-z"], cwd=ROOT)
    with tarfile.open(output / "untracked.tar.gz", "w:gz") as archive:
        for name in untracked.split(b"\0"):
            if name:
                archive.add(ROOT / os.fsdecode(name), arcname=os.fsdecode(name))
    write_json(output / "source-files.json", files)
    shutil.copy2(ROOT / "Cargo.lock", output / "Cargo.lock")
    (output / "features.txt").write_text(command(cargo + ["tree", "-p", PACKAGE, "--features", args.features, "-e", "features"]))
    rustc = ["rustc"] + ([f"+{args.toolchain}"] if args.toolchain else [])
    manifest = {"source": identity, "revision": command(["git", "rev-parse", "HEAD"]),
                "dirty": bool(command(["git", "status", "--porcelain"])),
                "rustc": command(rustc + ["-Vv"]), "cargo": command(cargo + ["-V"]),
                "lock_sha256": digest(ROOT / "Cargo.lock"), "features": args.features,
                "command": invocation, "executables": executables,
                "build_environment": {key: os.environ.get(key) for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "CARGO_BUILD_TARGET")}}
    write_json(output / "build.json", manifest)
    print(output / "build.json")


def cpu_evidence(cpu):
    """Record physical-core identity and policy; never pool logical CPUs implicitly."""
    base = Path(f"/sys/devices/system/cpu/cpu{cpu}")
    paths = ["topology/core_id", "topology/physical_package_id", "topology/thread_siblings_list",
             "cpufreq/scaling_governor", "cpufreq/scaling_driver", "cpufreq/scaling_min_freq",
             "cpufreq/scaling_max_freq", "cpufreq/energy_performance_preference"]
    policy = {name: (base / name).read_text().strip() if (base / name).exists() else None for name in paths}
    return {"logical_cpu": cpu, "host": platform.node(), "kernel": platform.release(), "machine": platform.machine(),
            "topology_policy": policy, "lscpu": json.loads(command(["lscpu", "-J"]))}


def run(args):
    """A fresh process and Criterion directory per case and round, even on failure."""
    artifact = args.build.resolve()
    build_info = json.loads(artifact.read_text())
    cases = [case.split(":", 1) for case in args.case]
    for target, case in cases:
        executable = artifact.parent / build_info["executables"][target]["file"]
        if digest(executable) != build_info["executables"][target]["sha256"]:
            raise RuntimeError(f"frozen executable changed: {target}")
        listed = command([str(executable), "--list", "--bench"])
        if f"{case}: benchmark" not in listed.splitlines():
            raise ValueError(f"unknown exact case: {target}:{case}")
    if args.cpu not in os.sched_getaffinity(0):
        raise ValueError("requested CPU is outside the allowed affinity")
    run_id = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    root = args.output.resolve() / run_id
    root.mkdir(parents=True)
    cpu = cpu_evidence(args.cpu)
    for round_index in range(1, args.rounds + 1):
        # Alternate order, preserving each case's exact round and CPU identity.
        ordered = cases if round_index % 2 else list(reversed(cases))
        for index, (target, case) in enumerate(ordered):
            directory = root / build_info["source"][:12] / f"cpu{args.cpu}" / f"round{round_index}" / f"{index}-{target}"
            directory.mkdir(parents=True)
            executable = artifact.parent / build_info["executables"][target]["file"]
            invocation = [str(executable), case, "--exact", "--bench", "--sample-size", str(args.samples),
                          "--warm-up-time", str(args.warmup), "--measurement-time", str(args.measurement)]
            env = os.environ.copy()
            env["CRITERION_HOME"] = str(directory / "criterion")
            env["PRIMUS_BENCH_METADATA"] = str(directory / "cases.jsonl")
            env.pop("PRIMUS_LUT_DIAGNOSTICS", None)
            record = {"label": args.label, "round": round_index, "case": case, "target": target,
                      "build": build_info, "cpu": cpu, "command": invocation,
                      "policy": {"samples": args.samples, "warmup": args.warmup, "measurement": args.measurement},
                      "status": "running"}
            write_json(directory / "run.json", record)
            print(f"round {round_index}: {case}", flush=True)
            with (directory / "stdout.log").open("w") as stdout, (directory / "stderr.log").open("w") as stderr:
                result = subprocess.run(invocation, cwd=ROOT, env=env, stdout=stdout, stderr=stderr,
                                        preexec_fn=lambda: os.sched_setaffinity(0, {args.cpu}))
            record.update(status="ok" if result.returncode == 0 else "failed", exit_code=result.returncode)
            write_json(directory / "run.json", record)
    print(root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    p = sub.add_parser("quick", help="common u64 workloads; also available as just bench")
    p.add_argument("operation", choices=QUICK_CASES)
    p.add_argument("backend", nargs="?", choices=BACKENDS,
                   help="default: all four backends; both NTRU backends for one-hot/lut/lut-create")
    p.add_argument("--fft", choices=("rustfft", "tfhe-fft"), help="Fourier engine (default: rustfft)")
    p.add_argument("--simd", action="store_true", help="use nightly and enable SIMD")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--list", action="store_true", help="list selected IDs without generating keys")
    mode.add_argument("--test", action="store_true", help="correctness smoke without statistical sampling")
    p.set_defaults(function=quick)
    p = sub.add_parser("build", help="compile and freeze explicitly selected targets")
    p.add_argument("--features", required=True)
    p.add_argument("--target", action="append", required=True)
    p.add_argument("--toolchain")
    p.add_argument("--output", type=Path, required=True)
    p.set_defaults(function=build)
    p = sub.add_parser("run", help="Linux CPU-pinned serial sampling of frozen binaries")
    p.add_argument("--build", type=Path, required=True)
    p.add_argument("--case", action="append", required=True, help="target:exact Criterion ID")
    p.add_argument("--cpu", type=int, required=True)
    p.add_argument("--rounds", type=int, default=3)
    p.add_argument("--label", required=True)
    p.add_argument("--output", type=Path, default=ROOT / "target/benchmark-results")
    p.add_argument("--samples", type=int, default=30)
    p.add_argument("--warmup", type=float, default=3)
    p.add_argument("--measurement", type=float, default=5)
    p.set_defaults(function=run)
    args = parser.parse_args()
    if args.action == "run" and (args.rounds < 1 or args.samples < 10 or args.warmup <= 0 or args.measurement <= 0):
        parser.error("rounds >= 1, samples >= 10 and positive durations required")
    try:
        args.function(args)
    except ValueError as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
