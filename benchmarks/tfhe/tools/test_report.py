"""Small synthetic evidence protects pairing/units without cryptographic setup."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import report


def observation(label="base", mean=2_000_000):
    return {"label": label, "round": 1, "cpu": 4, "case": "pbs/example/glwe/ntt/u64", "status": "ok", "mean_ns": mean,
            "run": {"cpu": {"logical_cpu": 4}, "round": 1, "policy": {"samples": 30}, "target": "pbs",
                    "build": {"features": "glwe-ntt", "rustc": "rustc", "lock_sha256": "lock", "executables": {"pbs": {"sha256": label}}}},
            "metadata": {"version": 2, "fixture_lifetime": "callback", "family": "glwe", "engine": "ntt", "word": "u64",
                         "operation": "pbs", "configuration": {"parameters": {"q": "100"}, "outputs": 1}}}


class ReportTests(unittest.TestCase):
    def test_ratio_direction_and_mismatch(self):
        base, candidate = observation(), observation("candidate", 2_200_000)
        self.assertAlmostEqual(report.compare(base, candidate, "revision")[1], 10)
        candidate["metadata"]["configuration"]["parameters"]["q"] = "200"
        self.assertEqual(report.compare(base, candidate, "revision"), ("parameters_or_workload_mismatch", None))
        self.assertEqual(report.compare(base, candidate, "arithmetic")[0], "arithmetic_cost_only")
        candidate["run"]["cpu"]["lscpu"] = {"lscpu": [{"field": "Model name:", "data": "another CPU"}]}
        self.assertEqual(report.compare(base, candidate, "arithmetic"), ("cpu_hardware_mismatch", None))

    def test_missing_failed_duplicate_and_separate_cpus(self):
        base, candidate = observation(), observation("candidate")
        candidate["cpu"] = 8
        result = list(report.pairs([base, candidate], "base", "candidate", None, "revision"))
        self.assertEqual([p["status"] for p in result], ["missing_pair", "missing_pair"])
        candidate = observation("candidate")
        candidate["status"] = "failed"
        self.assertEqual(report.compare(base, candidate, "revision")[0], "failed_or_incomplete_pair")
        candidate["status"] = "ok"
        result = list(report.pairs([base, copy.deepcopy(base), candidate], "base", "candidate", None, "revision"))
        self.assertEqual(result[0]["status"], "duplicate_pair")

    def test_plan_layout_is_not_ignored(self):
        base, candidate = observation(), observation("candidate")
        for row in (base, candidate):
            row["metadata"]["engine"] = "tfhe_fft"
            row["metadata"]["fft_plan"] = "runtime Measure(10ms); algorithm not exposed"
        base["metadata"]["configuration"]["fft_layout_fingerprint"] = "a"
        candidate["metadata"]["configuration"]["fft_layout_fingerprint"] = "b"
        self.assertEqual(report.compare(base, candidate, "algorithm"), ("fft_layout_mismatch", None))
        candidate["metadata"]["configuration"]["fft_layout_fingerprint"] = "a"
        self.assertIn("fft_algorithm_unobserved", report.compare(base, candidate, "algorithm")[0])

    def test_criterion_join_and_nanoseconds(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            row = observation()
            run = row["run"] | {k: row[k] for k in ("label", "round", "case", "status")}
            (root / "run.json").write_text(json.dumps(run))
            (root / "cases.jsonl").write_text(json.dumps(row["metadata"] | {"id": row["case"]}))
            data = root / "criterion/sanitized/new"
            data.mkdir(parents=True)
            (data / "benchmark.json").write_text(json.dumps({"full_id": row["case"]}))
            estimate = {"point_estimate": 2_000_000, "confidence_interval": {"lower_bound": 1_900_000, "upper_bound": 2_100_000}}
            (data / "estimates.json").write_text(json.dumps({k: estimate for k in ("mean", "median", "std_dev")}))
            result = report.read_case(root / "run.json")
            self.assertEqual(result["mean_ns"], 2_000_000)
            report.export([result], root / "report", [])
            self.assertIn("2.000000", (root / "report/report.md").read_text())
            (root / "cases.jsonl").unlink()
            self.assertEqual(report.read_case(root / "run.json")["status"], "missing_or_duplicate_evidence")


if __name__ == "__main__":
    unittest.main()
