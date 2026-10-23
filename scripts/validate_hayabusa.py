#!/usr/bin/env python3
"""Nonzero-detection A/B gate against an unmodified, pinned Hayabusa checkout.

Run after building evtx_dump and Hayabusa; see docs/canonical-jsonl-validation.md.
Artifacts are retained under --output for review. No conversion is used in path B.
"""
import argparse
import collections
import csv
import hashlib
import json
from pathlib import Path
import subprocess
import struct
from jsonschema import Draft202012Validator, FormatChecker


def run(argv, cwd, log, stdout=None):
    with log.open("wb") as diagnostics:
        subprocess.run([str(a) for a in argv], cwd=cwd, check=True,
                       stdout=stdout or diagnostics, stderr=diagnostics)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--hayabusa", type=Path, required=True, help="Hayabusa repository root")
    p.add_argument("--parser", type=Path, default=Path("target/release/evtx_dump"))
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--sample", type=Path, default=Path("samples/new-user-security.evtx"))
    args = p.parse_args()
    repo = Path(__file__).resolve().parents[1]
    parser = args.parser.resolve()
    hayabusa = args.hayabusa.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    sample = args.sample.resolve()
    binary = hayabusa / "target/release/hayabusa"
    jsonl = output / (sample.name + ".jsonl")
    with jsonl.open("wb") as stream:
        run([parser, "--canonical", "-o", "jsonl", "-t", "4", sample], repo,
            output / "export.log", stream)
    events = [json.loads(line) for line in jsonl.read_text().splitlines()]
    assert events, "No canonical events exported"
    assert all("_teg" in row for row in events)
    schema = json.loads((repo / "docs/canonical-jsonl-v1.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    for row in events:
        validator.validate(row)
    source_hash = hashlib.sha256(sample.read_bytes()).hexdigest()
    assert all(row["_teg"]["source"]["sha256"] == source_hash for row in events)
    for row in events:
        expected_uid = "sha256:" + hashlib.sha256(
            b"evtx-teg/v1\0" + source_hash.encode("ascii") +
            struct.pack("<Q", row["_teg"]["record"]["offset"])).hexdigest()
        assert row["_teg"]["event_uid"] == expected_uid, "UID disagrees with schema algorithm"
    # This third input is ONLY a test control proving metadata tolerance.
    stripped = output / "control-without-teg.jsonl"
    with stripped.open("w") as stream:
        for row in events:
            stream.write(json.dumps({k: v for k, v in row.items() if k != "_teg"}) + "\n")
    fields = ("RuleID", "RecordID", "Timestamp", "Level", "Computer", "Channel", "EventID")
    results = {}
    for label, source, flags in [("A", sample, []), ("B", jsonl, ["-J"]),
                                  ("metadata-control", stripped, ["-J"])]:
        dest = output / (label + ".csv")
        run([binary, "dfir-timeline", "-f", source, *flags, "-w", "-N", "-b",
             "--iso-8601", "--threads", "4", "-p", "verbose", "-o", dest,
             "--clobber"], hayabusa, output / (label + ".log"))
        with dest.open(encoding="utf-8-sig", newline="") as stream:
            rows = list(csv.DictReader(stream))
        assert rows, f"{label}: zero detections is a test failure"
        results[label] = collections.Counter(tuple(row[f] for f in fields) for row in rows)
    assert results["A"] == results["B"], (
        f"Detection mismatch: missing={results['A'] - results['B']}; extra={results['B'] - results['A']}")
    assert results["B"] == results["metadata-control"], "_teg changes detections"
    record_ids = {str(row["RecordNumber"]) for row in events}
    assert all(row[1] in record_ids for row in results["B"]), "Unknown source event"
    event_lookup = {(str(row["RecordNumber"]), str(row["Hostname"]), str(row.get("Channel")), str(row["EventID"])):
                    row["_teg"]["event_uid"] for row in events}
    assert all((row[1], row[4], row[5], row[6]) in event_lookup for row in results["B"]), \
        "Detection must map to an original EVTX event UID"
    if sample.name == "new-user-security.evtx":
        assert any(row[0] == "13edce80-2b02-4469-8de4-a3e37271dcdb" for row in results["A"]), \
            "Known account-creation rule did not fire"
    summary = {
        "schema": events[0]["_teg"]["schema"],
        "sample": sample.name, "sha256": source_hash, "events": len(events),
        "projection_notes_by_field": dict(collections.Counter(
            note["field"] for row in events for note in row["_teg"].get("projection_conflicts", []))),
        "detections": {label: sum(rows.values()) for label, rows in results.items()},
        "unique_rules": len({row[0] for row in results["A"]}),
        "compared_fields": fields, "equivalent": True,
        "hayabusa_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=hayabusa, text=True).strip(),
        "rules_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=hayabusa / "rules", text=True).strip(),
        "expected_differences": ["EvtxFile names the JSONL input in B; _teg.source retains EVTX provenance",
                                 "ExtraFieldInfo contains the canonical fields and metadata in B"],
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
