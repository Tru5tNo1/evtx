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
| `samples/Application.evtx` | 6,419 | 58 | 58 | 58 | 3 |
| PowerShell obfuscation (DeepBlueCLI) | 302 | 390 | 390 | 390 | 14 |
| PowerShell Defender disable (EVTX-to-MITRE-Attack) | 50 | 34 | 34 | 34 | 3 |
| PowerShell classic downgrade (YamatoSecurity) | 26 | 4 | 4 | 4 | 2 |

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
* [Application fixture, including collisions](validation/canonical-application.json)
* [PowerShell classic, module and ScriptBlock fixtures](validation/canonical-powershell.json)

## PowerShell detection regression coverage

The three PowerShell fixtures above are originals from
[`hayabusa-sample-evtx` at `0845333ecb4afcf64c55c6e10946383f168f308c`](https://github.com/Yamato-Security/hayabusa-sample-evtx/tree/0845333ecb4afcf64c55c6e10946383f168f308c).
CI checks out the exact files, verifies their SHA-256 hashes and requires known
malicious-PowerShell, Defender-tampering and downgrade Rule IDs. The results give
filenames, hashes, counts, required rules and pinned Hayabusa/rules revisions.

The obfuscation fixture includes 302 ScriptBlock events (4104), of which 68 have
`MessageTotal > 1`; the largest fragment has 19,659 characters. All 390 detections
match, including 69 `Potentially Malicious PwSh` detections. The Defender fixture
contains 800, 4103 and 4104 events, with four detections of the known
`Tamper Windows Defender - ScriptBlockLogging` rule. The classic fixture covers
400/403/600/800, including one detected PowerShell 2.0 downgrade. These are distinct
from `Tamper Windows Defender - PSClassic`, which targets event 600 and `Data`.
The fixtures do not reproduce every rule or event shape in a real collection.

The test also compares `ScriptBlockText`, `ScriptBlockId`, `MessageNumber` and
`MessageTotal` between the root aliases, `Event.EventData` and retained XML.
The two JSON projections must be identical. XML comparison accounts explicitly
for XML's CR/CRLF normalization; it does not prove original byte equality for
line endings. Fragment numbers and totals remain intact. Neither the exporter
nor the pinned Hayabusa detection paths reconstructs multi-event ScriptBlocks.
A rule whose required strings span different fragments can miss in both paths;
this alone cannot explain an A/B difference.

Source review: both input paths reach
[`create_rec_info`/`extract_fields`](https://github.com/Yamato-Security/hayabusa/blob/a5f0e010893a8c388e693019e3fbb8f374a9f9c0/src/detections/utils.rs#L367).
The shared [classic-field extractor](https://github.com/Yamato-Security/hayabusa/blob/a5f0e010893a8c388e693019e3fbb8f374a9f9c0/src/detections/field_extract.rs#L10)
handles 400/403/600/800; it is not a 4104 fragment reassembler.

For a fair A/B comparison, the harness disables native file/rule channel filtering
with `-A -a`. JSON mode already disables these filters and rejects those flags.
The native optimization can select rules from only the first channel of a
mixed-channel file: the Defender fixture otherwise produced **zero native
detections**. That zero was treated as failure, not accepted as equivalence.

These positive fixture results do **not** resolve the larger user-reported corpus:
498,312 native detections versus 416,561 through JSONL, a difference of 81,751.
The event counters also differ (8,884,077 versus 8,252,361), but native Hayabusa
counts attempted records before handling parser errors. Consequently the counter
difference is not proof of that many valid events being lost. The collection
requires per-file coverage and per-event comparison using identical versions,
rules and filters. An export that stopped on error may be incomplete. No claim
of corpus-wide equivalence or of a confirmed ScriptBlock parsing defect is made.

## Projection and evidence regressions

Schema 1.1.0 regression coverage includes the real Application records with
different `System.Version`/`EventData.Version` and `System.EventID`/`EventData.EventID`.
The original 1.0.0 exporter rejected this fixture. Standard Hayabusa aliases now
select the system value for these names, while the unaliased `Task` field selects
the payload value. A synthetic regression exercises exactly that reported Task
collision and verifies both original structured values remain intact, with an
explicit `_teg.projection_conflicts` entry.

The expanded A/B test initially found 14 missing MSI detections because unnamed
Data was an object/array in the compatibility projection. The pinned native
Hayabusa renderer concatenates that text into a scalar. Version 1.1.0 matches
that behavior only in root `Data`, retains the original item array under
`Event.EventData.Data.#text`, and records the projection in `_teg`. All 58 native
Application detections now match, including the MSI suspicious-location rule.

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

The final local runs passed 143 tests in the main crate and 20 in `utf16-simd`,
with zero failures and four deliberately ignored tests across both runs.
Release build, no-default-features library check and formatting check passed.
Clippy completed successfully with repository warnings; it is not configured as
a warnings-as-errors gate. Hosted CI validates each pushed PR revision separately.

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
| Original JSONL | 1 | 0.0713 | 421.8 | 13,184 |
| Current legacy JSONL | 1 | 0.0738 | 407.6 | 13,184 |
| Canonical JSONL | 1 | 1.1575 | 26.0 | 13,184 |
| Original separate attributes | 1 | 0.2791 | 107.7 | 13,184 |
| Original JSONL | 4 | 0.0467 | 643.7 | 13,184 |
| Current legacy JSONL | 4 | 0.0417 | 721.2 | 13,184 |
| Canonical JSONL | 4 | 0.4520 | 66.5 | 13,184 |
| Original separate attributes | 4 | 0.1235 | 243.5 | 14,112 |

Canonical output is 214,610,017 bytes versus 53,439,594 bytes for original JSONL
(4.02×); both contain exactly 62,031 records. Canonical mode emits approximately
137,237 events/s at four threads on this fixture, with bounded chunk concurrency.
It is **9.7× slower than original lossy JSONL** at four threads, and 3.7× slower
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
