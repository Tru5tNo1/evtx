# Canonical forensic JSONL — `evtx-teg/1.1.0`

One UTF-8 JSON object per line, without banners or a JSON array. The same file is
input to Hayabusa `-J` and the Temporal Evidence Graph. No post-export conversion
is required. JSON Schema: [canonical-jsonl-v1.schema.json](canonical-jsonl-v1.schema.json).

```sh
cargo build --release --locked --bin evtx_dump
target/release/evtx_dump --canonical -o jsonl evidence/Security.evtx > Security.evtx.jsonl
target/release/evtx_dump --canonical -o jsonl evidence/ -f exported/
```

The second command mirrors `evidence/host/site/*.evtx` to
`exported/host/site/*.evtx.jsonl`. It processes files sequentially and chunks in
parallel. Filenames retain `.evtx` to avoid basename collisions. Directory input
requires a separate output directory; symlink input entries are rejected.
Existing output files require confirmation or `--no-confirm-overwrite`.
Single-file and stdin input remain supported. Stdin is spooled to a temporary
seekable file on disk, as in the original CLI, rather than accumulated in RAM.

## Record contract

| Member | Meaning |
| --- | --- |
| `Event.System` | Windows system fields, with sibling `*_attributes` objects |
| `Event.System.EventID` | Unsigned JSON integer; qualifiers remain in `EventID_attributes` |
| `Event.System.Provider_attributes` | Provider attributes, including `Name`, `Guid`, and unknown attributes when present |
| `Event.System.TimeCreated_attributes.SystemTime` | Original event timestamp, precision retained |
| `Event.EventData` | Named `Data` values projected to member names, retaining legacy scalar types |
| `Event.UserData` | Provider-specific nested structure; attributes normalized recursively |
| root system/payload members | Compatibility aliases for Hayabusa's flat importer, not a second export |
| `Hostname` | Alias of `Event.System.Computer` |
| `SourceName` | Alias of `Event.System.Provider_attributes.Name` |
| `RecordNumber` | Alias of `Event.System.EventRecordID`, falling back to the record header ID |
| `@timestamp` | Alias of `Event.System.TimeCreated_attributes.SystemTime` |
| `_teg` | Forensic metadata; never injected inside Windows `Event` fields |

Absent `EventData` or `UserData` is not fabricated. Empty containers may be null.
Aliases follow the precedence policy below. They are redundant members of one
document: graph consumers should use `Event` and `_teg`, while Hayabusa uses the
flat members. Consumers must not treat both projections as separate events.

## Preservation and projection

The detection projection is deliberately not the evidence representation.
The upstream JSON renderer flattens named `Data`, aggregates positional data,
suffixes repeated ordinary elements, and can discard unnamed siblings or extra
attributes at named-data sites. Deserializing duplicate JSON members also keeps
only the last value. Therefore **`Event` and root aliases alone are not lossless**.

`_teg.rendered_xml` always contains the complete XML rendering of that record,
before JSON projection. It retains element/attribute names and values, unknown
attributes, repeated names, unnamed `Data`, and sibling order supported by the
parser. This is the authoritative representation for those ambiguities; consumers
must not infer that an absent projected field was absent in the evidence.
It is reconstructed XML, not the original file bytes or an independently acquired
XML export. BinXML type descriptors, template compression and byte layout are
retained in the original EVTX, identified by hash and offset. Existing parser
limitations still apply (for example, unsupported BinXML token types fail).

Starting with 1.1.0, payload/system name collisions do not abort the export.
The flat compatibility projection follows the pinned Hayabusa 4.2.0 alias table:

* Names resolved through `Event.System` (`EventID`, `Version`, `Channel`,
  `Computer`, `Keywords`, `Level`, provider/security/execution attribute objects,
  `Provider_Name`, `SearchFilter`, `ServerName`) select the system value.
* Unaliased names, notably **`Task`**, select the payload value when present.
  For example `Event.System.Task = 1` and `Event.EventData.Task = "custom"`
  produce root `Task = "custom"`, while retaining both structured values.
* `Hostname`, `SourceName`, `RecordNumber` and `@timestamp` always select the
  system-derived compatibility values used by the importer.
* Different same-named fields in both payload containers select `EventData`
  before `UserData`. Both containers remain intact under `Event`.
* Reserved payload keys `Event`, `_teg`, object-valued `result` and non-null
  `rows` are omitted only from root aliases, preventing accidental selection of
  the Splunk importer. The payload remains under its original `Event` container.
* Unnamed `Data.#text` strings are concatenated without a separator in root
  `Data`, matching the pinned native Hayabusa EVTX renderer. The structured
  `Event.EventData.Data.#text` values and XML evidence retain the original items,
  empties and ordering. This normalization is also recorded in the metadata.

Every unequal or reserved-key collision is recorded in
`_teg.projection_conflicts`, with `field`, `selected_source`, `other_source` and
`reason`. It is an empty array for records without collisions. This is an
explicit detection projection, not a destructive merge of the event. Graph
consumers use the original `Event` paths and evidence, not ambiguous root aliases.
The policy is pinned to the standard alias configuration; custom alias tables
or explicit paths requiring both colliding values need separate validation.
Version 1.0.0 rejected such records; 1.1.0 accepts them with this documented
projection and additional metadata. Existing event UIDs do not change.

Parser/serialization failures still return nonzero.
An error can leave partial output; treat an export as valid only after exit 0.
The original evidence is never rewritten. Unknown names colliding with generated
`*_attributes` names remain recoverable from `_teg.rendered_xml`.

## Provenance and time

`_teg.source` contains `path`, lowercase hexadecimal SHA-256 of the entire EVTX,
and byte `size`. For a directory export the path is relative to its input root,
including machine directories; single-file input retains the supplied path.
Stdin is identified by its supplied stdin path and the hash of the spooled bytes.

`_teg.record` contains the zero-based absolute EVTX record-header byte `offset`,
header `record_id` and `recovered` flag. Offsets account for empty chunks and
recovered records. `event_uid` is:

```text
"sha256:" + hex(SHA256(
    ASCII("evtx-teg/v1") || 0x00 ||
    ASCII(lowercase source SHA-256 hex) ||
    little_endian_u64(record_header_absolute_offset)
))
```

It identifies an event occurrence within an immutable evidence artifact, even if
record IDs repeat. Changing thread count, output order, path, acquisition time or
ingestion time does not change it. An identical EVTX copied to another machine
directory has the same event UIDs and different provenance paths. A graph may
store those paths as distinct acquisition/observation edges. Changing any file
bytes changes the artifact hash and therefore its event UIDs. It is not a
cross-artifact identity for logically equivalent events from different exports.

`_teg.event_time` is `SystemTime`; `_teg.record_header_time` independently retains
the EVTX header timestamp. `_teg.ingested_at` defaults to export time (UTC RFC3339).
`_teg.acquired_at` is null unless the examiner supplies the actual acquisition
time. Neither file modification time nor export time is used to invent acquisition
time. Supply `--acquired-at RFC3339` and, for reproducibility,
`--ingested-at RFC3339`. Timestamp inputs are validated.

## Actual Hayabusa importer contract and limits

Inspected unmodified Hayabusa 4.2.0 commit
`a5f0e010893a8c388e693019e3fbb8f374a9f9c0`:

* [`src/detections/utils.rs`, `read_jsonl_to_value`](https://github.com/Yamato-Security/hayabusa/blob/a5f0e010893a8c388e693019e3fbb8f374a9f9c0/src/detections/utils.rs#L146)
  wraps each entire input line as `{"Event":{"EventData":line}}`.
* [`src/main.rs`, `analysis_json_file`](https://github.com/Yamato-Security/hayabusa/blob/a5f0e010893a8c388e693019e3fbb8f374a9f9c0/src/main.rs#L2838)
  copies this flat object into `System` and `UserData`, takes the record number
  from `RecordNumber`, provider name from `SourceName`, and computer from `Hostname`.
* [`src/detections/message.rs`, `get_event_time`](https://github.com/Yamato-Security/hayabusa/blob/a5f0e010893a8c388e693019e3fbb8f374a9f9c0/src/detections/message.rs#L434)
  reads `Event.System.@timestamp` for JSON input, rather than `SystemTime`.
* `evtx_to_jsons` uses its EVTX parser with `separate_json_attributes(true)` for
  native EVTX input. Our old default JSONL has inline `#attributes`, so neither
  the old default JSONL nor just enabling `--separate-json-attributes` is sufficient.

This is why simply emitting an `Event` envelope can load successfully yet lose
detections. The canonical file includes the required flat projection directly.
Unknown root `_teg` is accepted; the A/B test also removes it as a test-only
control and requires identical, nonzero detections.

There is a format-only compatibility limit: Hayabusa overwrites
`System.Provider_attributes` with **only** `Name` and replaces `UserData` with the
flat input. Rules requiring `System.Provider_attributes.Guid`, strict separation
of same-named `EventData` and `UserData` fields, exact root-key matching, or
conflicting flat/system field values cannot have universal equivalence under
this importer. No JSON field can prevent those assignments. Provider `Guid` and
all original data remain in our structured event/evidence, but the importer may
not expose them to such rules. No Hayabusa changes or alternate pipeline are
introduced here. The tested equivalence applies to the pinned rule set and
fixtures in the [validation report](canonical-jsonl-validation.md), not every
possible future rule or malformed EVTX.

Hayabusa's `EvtxFile` output names the JSONL in path B. Map its `RecordID`,
`Computer`, `Channel`, `EventID` and timestamp to `_teg` for original EVTX provenance.
Its `ExtraFieldInfo` can include our envelope and metadata; it is not expected
to be byte-identical between A and B.

## Performance and versioning

The existing bounded chunk pipeline remains in use (at most twice the selected
worker count in flight). JSON and XML use cached compiled template programs,
with the existing fallback only for unsupported template shapes. Canonical mode
does **not** enable the slow `--separate-json-attributes` materialization path.
Normalization and the metadata envelope are constructed per record inside chunk
workers. Memory scales with concurrent chunks and record size, not file length.
An initial streaming SHA-256 pass over the same seekable handle establishes
artifact identity; immutable evidence input is assumed during export.

Canonical output is larger and more expensive than the original lossy JSONL:
it includes XML evidence, aliases, provenance and hashing. See measured costs,
including the original parser baseline, in the validation report. No claim of
baseline-equivalent throughput is made.

Breaking field/identity/projection changes require a new major schema version.
Additive optional metadata uses a minor version; clarifications use a patch.
Readers should accept unknown fields and explicitly reject unsupported major
versions. The graph implementation itself is outside this parser change.
