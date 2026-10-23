#!/usr/bin/env python3
"""Interleaved warm-cache CLI benchmark, including hashing, rendering and metadata.

Linux wait4 reports per-process peak RSS. Stdout goes to /dev/null for every mode.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import statistics
import subprocess
import tempfile
import time


def measure(argv):
    start = time.perf_counter()
    with open(os.devnull, "wb") as sink, tempfile.TemporaryFile() as diagnostics:
        child = subprocess.Popen([str(a) for a in argv], stdout=sink, stderr=diagnostics)
        _, status, usage = os.wait4(child.pid, 0)
        child.returncode = os.waitstatus_to_exitcode(status)
        diagnostics.seek(0)
        error = diagnostics.read().decode()
        assert child.returncode == 0, error
    return {"seconds": time.perf_counter() - start, "peak_rss_kib": usage.ru_maxrss}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--original", type=Path, required=True)
    p.add_argument("--parser", type=Path, default=Path("target/release/evtx_dump"))
    p.add_argument("--sample", type=Path, default=Path("samples/security_big_sample.evtx"))
    p.add_argument("--runs", type=int, default=7)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    assert args.runs > 0, "--runs must be positive"
    modes = {}
    for threads in [1, 4]:
        for name, binary, flags in [("original", args.original, []),
                                    ("legacy-current", args.parser, []),
                                    ("canonical", args.parser, ["--canonical"]),
                                    ("separate-attributes", args.original, ["--separate-json-attributes"])]:
            modes[f"{name}/{threads}"] = [binary.resolve(), "-o", "jsonl", "-t", str(threads), *flags, args.sample.resolve()]
    for command in modes.values():
        measure(command)
    samples = {mode: [] for mode in modes}
    for index in range(args.runs):
        order = list(modes) if index % 2 == 0 else list(reversed(modes))
        for mode in order:
            samples[mode].append(measure(modes[mode]))
    size = args.sample.stat().st_size
    report = {"sample": str(args.sample), "bytes": size,
              "sha256": hashlib.sha256(args.sample.read_bytes()).hexdigest(),
              "runs": args.runs, "machine": dict(zip(
                  ["sysname", "nodename", "release", "version", "machine"], os.uname())), "modes": {}}
    report["binaries"] = {"original_sha256": hashlib.sha256(args.original.read_bytes()).hexdigest(),
                          "parser_sha256": hashlib.sha256(args.parser.read_bytes()).hexdigest()}
    report["output_sizes"] = {}
    for name in ["original", "canonical"]:
        child = subprocess.Popen([str(a) for a in modes[name + "/1"]], stdout=subprocess.PIPE)
        total = records = 0
        while chunk := child.stdout.read(1024 * 1024):
            total += len(chunk)
            records += chunk.count(b"\n")
        assert child.wait() == 0
        child.stdout.close()
        report["output_sizes"][name] = {"bytes": total, "records": records}
    for mode, runs in samples.items():
        median = statistics.median(row["seconds"] for row in runs)
        report["modes"][mode] = {"median_seconds": median, "mib_per_second": size / 1048576 / median,
                                "peak_rss_kib": max(row["peak_rss_kib"] for row in runs), "samples": runs}
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
