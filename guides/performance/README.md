# Performance decisions and measurements

English | [简体中文](README.zh_CN.md)

This directory records performance choices, costs and historical evidence.
Current APIs and contracts are in the [development guide](../development/README.md).
Each report states its revision, workload and limits; historical measurements
are not current validation or security guarantees.

## Topic reports

| Report | Decision and scope |
| --- | --- |
| [Sparse arithmetic](sparse-arithmetic.md) | Retain the documented pair/group/four-way and compact-reduction choices within their numerical and workload bounds. Reassessments preserve adverse results; gains from different baselines cannot be added. |
| [Sparse layout and batching](sparse-layout-and-batching.md) | Retain paired NTRU LUT blind rotation. Tiles, first-bucket specialization, streaming, tile-major keys and shared projection did not justify their costs in the tested workloads. |
| [Sparse parameters and consumers](sparse-parameters.md) | Replica/bucket and decomposition candidates change matching, storage and error budgets. PBS success does not validate CBS output scales or establish security/DFR estimates. |
| [Preparation and workspace measurements](workspace-measurements.md) | Preparation, alignment and scratch sharing have separate costs. Less memory or equal buffer shapes does not prove faster complete requests. |
| [Paper comparison](sparse-paper-comparison.md) | Distinguish paper tables, earlier Primus/OpenFHE studies and the later supplied author fork/HEXL experiment. Parameters, sampling, return paths and builds differ; the later raw records are not retained. |
| [Fourier first-product write](fourier-first-write.md) | Retain clear-then-accumulate. First-product overwrite helps measured binary PBS/classic CBS profiles, but sparse CBS and process variability do not justify a global replacement. All 54 build-valid pairs remain, including one FFT-plan mismatch. |

## Current benchmarks

Benchmarks live in their backend or LUT crate. Use the [TFHE benchmark commands](../development/testing.md#tfhe-benchmarks)
and [high-precision LUT commands](../development/testing.md#high-precision-lut-benchmarks);
features and timing boundaries are described there and in each crate's bench file.
The [parameter directory](../development/tfhe-parameters.md#current-backend-benchmarks)
explains current fixtures. Historical workload IDs are evidence labels, not
current targets. The removed centralized runner and report tools are not required.

## Measurement method

1. Fix the revision, binary, CPU, toolchain, features, parameters and complete
   operation. Verify that each binary contains the intended implementation;
   parameter changes must be distinguished from arithmetic/layout changes.
2. Time one request per iteration with unrelated preparation and checks outside
   timing. Record construction costs separately. Validate the relevant numerical
   contract, including gadget output scales when decryption alone is insufficient.
3. Compare independent processes with controlled run order. Keep adverse results,
   unchanged-path controls and confirmation runs; one process's confidence
   interval does not measure variation between processes.
4. Decide from repeatable complete-request gains together with numerical bounds,
   storage, code size and maintenance costs. Stage acceleration or fewer
   allocations alone is insufficient.

Historical CPU 4/8 measurements use the 96/32 MiB L3 groups of **one** Ryzen 9
9955HX3D, not independent platforms. Mixed results do not establish a universal
regression or a cache-writeback cause. Allocation traffic is not retained heap,
peak or RSS; elapsed time alone does not diagnose memory traffic. Each report
keeps its measurement settings and untested paths alongside the results.

## Evidence limits

Six CSVs in [data/](data/) belong to the arithmetic, workspace and Fourier reports,
which explain their columns and provenance. Temporary candidates, raw binaries
and some source adaptations are no longer retained; a historical summary does
not promise full reproduction. Old LUT measurements with content-dependent
selection cannot be treated as measurements of the current fixed complete tree.

Revisit a choice in its topic report, preserving its comparison boundary.
Keep ordinary validation in the [testing guide](../development/testing.md),
public contracts in rustdoc/README and local algorithm reasons beside the code.
