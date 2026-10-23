# Canonical JSONL validation

Validated on 2026-10-23, Linux x86-64, Rust/Cargo 1.99.1, default Cargo features,
release profile, four CPU quota cores, 32 GiB memory. Hayabusa was built from
unmodified commit `a5f0e010893a8c388e693019e3fbb8f374a9f9c0` (4.2.0), with its
rules submodule at `e9a98d49313eed67fe1a2c21c0b108e04fdebe66`.

## Actual detections, not just successful JSON parsing

| Original EVTX fixture | Events exported | A: native EVTX | B: canonical JSONL `-J` | Test control without `_teg` | Unique rules |
| --- | ---: | ---: | ---: | ---: | ---: |
| `samples/new-user-security.evtx` | 4 | 3 | 3 | 3 | 3 |
| `samples/system.evtx` | 1,881 | 138 | 138 | 138 | 13 |

Detection multisets match exactly on **RuleID, RecordID, Timestamp, Level,
Computer, Channel and EventID**, including multiplicity. Output order is not used
as identity. The account fixture fires the known rule
`13edce80-2b02-4469-8de4-a3e37271dcdb` (Local User Account Created), as well as group
membership rules. The System fixture exercises provider-specific `UserData`.
Every detected record maps to an event UID and original EVTX provenance.
Every JSONL record passes the versioned JSON Schema with date-time format checks.

The metadata-free third input is a test-only negative control for interference;
it is not an additional production export. Path B consumes the exact canonical
output from `evtx_dump`, without converting it.

Expected differences are confined to `EvtxFile` (Hayabusa reports its actual JSONL
input path) and `ExtraFieldInfo` (extra aliases, envelope and metadata). Rule IDs,
source record identity, timestamps and severity have no differences on these
fixtures. The original EVTX path, artifact hash and physical offset remain in
`_teg`, independently of Hayabusa's displayed filename.

Machine-readable results include fixture SHA-256 values and pinned revisions:

* [Account fixture](validation/canonical-account.json)
* [System fixture](validation/canonical-system.json)

An additional attempted export of `samples/sysmon.evtx` found an invalid chunk
header at physical chunk 9. Canonical mode correctly returned nonzero rather
than certifying a partial export. This corrupt fixture is not counted as a
successful A/B validation; a regression test requires its explicit failure.

The [schema document](canonical-jsonl-v1.md#actual-hayabusa-importer-contract-and-limits)
records format-only limits found in the importer. The A/B results are not proof
of equivalence for arbitrary rules relying on provider GUIDs that Hayabusa
overwrites, or payload/system alias collisions. Hayabusa source was not modified.

## Automated verification

```sh
export CARGO_BUILD_JOBS=4
cargo test --locked
cargo test --locked --manifest-path utf16-simd/Cargo.toml
cargo check --locked --no-default-features --lib
cargo build --release --locked --bin evtx_dump

git clone https://github.com/Yamato-Security/hayabusa.git /tmp/hayabusa
git -C /tmp/hayabusa checkout a5f0e010893a8c388e693019e3fbb8f374a9f9c0
git -C /tmp/hayabusa submodule update --init
cargo build --release --locked --manifest-path /tmp/hayabusa/Cargo.toml
python3 -m venv /tmp/evtx-validation-venv
/tmp/evtx-validation-venv/bin/pip install jsonschema==4.25.1
/tmp/evtx-validation-venv/bin/python scripts/validate_hayabusa.py \
  --hayabusa /tmp/hayabusa --output /tmp/canonical-account
/tmp/evtx-validation-venv/bin/python scripts/validate_hayabusa.py \
  --hayabusa /tmp/hayabusa --sample samples/system.evtx --output /tmp/canonical-system
```

Use fresh output directories or Hayabusa's clobber option (the script passes it).
The script raises on a failed process, zero detections, missing known rule,
schema/UID validation errors, unknown source record, or unequal detection
multisets. Raw JSONL, CSV, logs and summaries remain in its output directory.
[The CI workflow](../.github/workflows/canonical-jsonl.yml) runs this same gate
against the pinned, unmodified importer and uploads its artifacts. Local success
does not imply that hosted CI has already run.

Rust tests additionally cover numeric/qualified EventID, unknown attributes,
repeated and unnamed XML evidence, fast/general projection parity, collision
errors, source overwrite rejection, directory hierarchy, stdin/file identity,
explicit acquisition time, parallel determinism, and physical offsets past
skipped empty chunks. XML evidence is compared against the original XML renderer
for all 2,261 events in `samples/security.evtx`.

The final local runs passed 142 tests in the main crate and 20 in `utf16-simd`,
with zero failures and four deliberately ignored tests across both runs.
Release build, no-default-features library check and formatting check passed.
Clippy completed successfully with repository warnings; it is not configured as
a warnings-as-errors gate. Hosted CI remains to be run after opening the PR.

## Benchmark against the original parser

Baseline: `da613729880438bed1aabc8ba32858f3cc39bb62`, built before modifications
with the same Rust toolchain, release profile and default features. The original
binary was preserved outside the checkout. No PGO, fast allocator or custom
`RUSTFLAGS` were enabled in either build.

Input: `samples/security_big_sample.evtx`, 30.07 MiB, 62,031 records. Seven
interleaved measurements per mode after one warmup; output discarded equally
to `/dev/null`. Canonical measurements include file hashing, both compiled
renderers, normalization, aliases and all metadata/evidence. They are not
parser-only timings.

| Mode | Threads | Median seconds | Input MiB/s | Peak RSS KiB |
| --- | ---: | ---: | ---: | ---: |
| Original JSONL | 1 | 0.0764 | 393.4 | 13,184 |
| Current legacy JSONL | 1 | 0.0695 | 432.9 | 13,184 |
| Canonical JSONL | 1 | 1.0915 | 27.5 | 13,184 |
| Original separate attributes | 1 | 0.2695 | 111.6 | 13,184 |
| Original JSONL | 4 | 0.0355 | 847.2 | 13,184 |
| Current legacy JSONL | 4 | 0.0385 | 781.7 | 13,184 |
| Canonical JSONL | 4 | 0.5271 | 57.0 | 13,184 |
| Original separate attributes | 4 | 0.1086 | 276.8 | 14,064 |

Canonical output is 213,059,242 bytes versus 53,439,594 bytes for original JSONL
(3.99×); both contain exactly 62,031 records. Canonical mode emits approximately
117,683 events/s at four threads on this fixture, with bounded chunk concurrency.
It is **14.9× slower than original lossy JSONL** at four threads, and 4.9× slower
than the original separate-attributes output, which lacks the evidence,
provenance and compatibility envelope. These are materially different workloads;
the overhead is a cost, not a throughput improvement. The legacy measurements
vary between runs and do not establish a legacy speedup.

RSS comes from Linux `wait4().ru_maxrss` for each process lifecycle, including
the fork/exec launch floor of the Python harness. This is an observed upper bound
for this run, not a precision heap profile or a proof for arbitrary record sizes.
The implementation bounds in-flight chunks to `2 * num_threads`; it does not
collect the file's events in memory. Stdin spooling uses disk.

[Raw benchmark samples and binary hashes](validation/canonical-benchmark.json)
are retained. Reproduce after preserving/building the original binary outside
this checkout:

```sh
python3 scripts/benchmark_canonical.py \
  --original /path/to/original-evtx_dump --runs 7 \
  --output /tmp/canonical-benchmark.json
```

The initial DOM implementation was replaced with borrowed JSON fragments for
common Windows records; complex payloads use the checked general projection.
Performance of unusual `UserData`, exceptionally large records, other platforms
and cold storage is not established by this benchmark.
