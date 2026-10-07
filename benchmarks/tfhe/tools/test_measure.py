"""Protect the short command's workload selection and backend/feature mapping."""
import argparse
import re
import subprocess
import sys
import unittest

import measure


def options(**changes):
    return argparse.Namespace(**({"operation": "pbs", "backend": None, "fft": None,
                                 "simd": False, "list": False, "test": False} | changes))


class QuickTests(unittest.TestCase):
    def test_filters_keep_the_common_workload_bounded(self):
        cases = [
            ("pbs", "pbs/binary/shortint_2_2/KeyswitchBootstrap/complete/glwe/ntt/u64",
             "pbs/binary/shortint_2_2/BootstrapKeyswitch/complete/glwe/ntt/u64"),
            ("sparse", "sparse_pbs/fixed_weight/classic/complete/ntru/ntt/u64",
             "sparse_pbs/fixed_weight/classic/complete/ntru/rustfft/u32"),
            ("cbs", "cbs/sparse/complete/ntru/ntt/u64",
             "cbs/one_hot/sparse/M4/full/ntru/ntt/u64"),
            ("one-hot", "cbs/one_hot/sparse/M4/nonzero/ntru/ntt/u64",
             "cbs/sparse/complete/ntru/ntt/u64"),
            ("mvb", "mvb/sparse/D8_k3/factorized/ntru/ntt/u64",
             "mvb/classic/D64_k17/factorized/ntru/ntt/u64"),
            ("lut", "high_precision_lut/classic/c8_d5_o8/evaluate/lookup/ntt/u64",
             "high_precision_lut/classic/c8_d5_o8/dense_seed42/evaluate/lookup/ntt/u64"),
            ("lut-create", "high_precision_lut/classic/c8_d5_o8/create_lut_and_drop/lookup/ntt/u64",
             "high_precision_lut/classic/c8_d5_o8/evaluate/lookup/ntt/u64"),
        ]
        for operation, included, excluded in cases:
            with self.subTest(operation=operation):
                pattern = measure.quick_command(options(operation=operation))[-1]
                self.assertRegex(included, pattern)
                self.assertIsNone(re.search(pattern, excluded))

    def test_backend_features_and_unsupported_pairs(self):
        cases = [
            (options(), "glwe-ntt,glwe-fourier,ntru-ntt,ntru-fourier,rustfft", "pbs"),
            (options(operation="one-hot"), "ntru-ntt,ntru-fourier,rustfft", "cbs"),
            (options(operation="lut"), "ntru-ntt,ntru-fourier,rustfft,lut", "high_precision_lut"),
            (options(fft="tfhe-fft"), "glwe-ntt,glwe-fourier,ntru-ntt,ntru-fourier,tfhe-fft", "pbs"),
            (options(backend="glwe-ntt"), "glwe-ntt", "pbs"),
            (options(backend="glwe-fourier"), "glwe-fourier,rustfft", "pbs"),
            (options(operation="lut", backend="ntru-fourier", fft="tfhe-fft", simd=True, test=True),
             "ntru-fourier,tfhe-fft,lut,simd", "high_precision_lut"),
        ]
        for args, features, target in cases:
            with self.subTest(features=features):
                command = measure.quick_command(args)
                self.assertEqual(command[command.index("--features") + 1], features)
                self.assertEqual(command[command.index("--bench") + 1], target)
                self.assertEqual("+nightly" in command, args.simd)
                self.assertEqual("--test" in command, args.test)
        for args in [options(operation="lut", backend="glwe-ntt"),
                     options(operation="one-hot", backend="glwe-fourier"),
                     options(backend="ntru-ntt", fft="rustfft")]:
            with self.assertRaises(ValueError):
                measure.quick_command(args)

    def test_missing_operation_does_not_start_a_benchmark(self):
        result = subprocess.run([sys.executable, measure.__file__, "quick"],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("required: operation", result.stderr)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
