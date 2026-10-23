use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

fn export(path: &str, threads: &str) -> Vec<Value> {
    let output = assert_cmd::cargo::cargo_bin_cmd!("evtx_dump")
        .args([
            "-o",
            "jsonl",
            "--canonical",
            "-t",
            threads,
            "--ingested-at",
            "2026-10-23T00:00:00Z",
            path,
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    String::from_utf8(output)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[test]
fn original_evtx_exports_stable_unique_events_with_hayabusa_aliases() {
    let one = export("samples/new-user-security.evtx", "1");
    let parallel = export("samples/new-user-security.evtx", "4");
    assert!(!one.is_empty());
    assert_eq!(one, parallel);
    let mut ids = BTreeSet::new();
    let mut detection_event = false;
    for row in one {
        let system = &row["Event"]["System"];
        assert_eq!(row["EventID"], system["EventID"]);
        assert!(row["EventID"].is_u64());
        assert_eq!(row["RecordNumber"], system["EventRecordID"]);
        assert_eq!(row["Hostname"], system["Computer"]);
        assert_eq!(row["SourceName"], system["Provider_attributes"]["Name"]);
        assert_eq!(
            row["@timestamp"],
            system["TimeCreated_attributes"]["SystemTime"]
        );
        assert_eq!(row["_teg"]["event_time"], row["@timestamp"]);
        assert_eq!(row["_teg"]["schema"], "evtx-teg/1.1.0");
        assert!(row["_teg"]["acquired_at"].is_null());
        assert_eq!(row["_teg"]["source"]["sha256"].as_str().unwrap().len(), 64);
        assert!(ids.insert(row["_teg"]["event_uid"].as_str().unwrap().to_owned()));
        assert!(row["_teg"]["rendered_xml"]
            .as_str()
            .unwrap()
            .contains("<Event"));
        if row["EventID"] == 4720 {
            detection_event = true;
            assert_eq!(
                row["TargetUserName"],
                row["Event"]["EventData"]["TargetUserName"]
            );
        }
    }
    assert!(
        detection_event,
        "fixture must contain known account-creation detections"
    );
}

#[test]
fn application_evtx_with_real_payload_system_collisions_exports_completely() {
    let rows = export("samples/Application.evtx", "4");
    let mut parser = evtx::EvtxParser::from_path("samples/Application.evtx").unwrap();
    let original: Vec<_> = parser.records().map(|r| r.unwrap()).collect();
    assert_eq!(rows.len(), original.len());
    let mut conflicts = BTreeSet::new();
    for row in rows {
        for collision in row["_teg"]["projection_conflicts"].as_array().unwrap() {
            conflicts.insert(collision["field"].as_str().unwrap().to_owned());
        }
        assert_eq!(row["EventID"], row["Event"]["System"]["EventID"]);
    }
    assert!(conflicts.contains("Version"));
    assert!(conflicts.contains("EventID"));
}

#[test]
fn directory_export_preserves_machine_hierarchy_and_identity_after_move() {
    let input = tempfile::tempdir().unwrap();
    let output = tempfile::tempdir().unwrap();
    for machine in ["host-a", "site/host-b"] {
        let dir = input.path().join(machine);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::copy("samples/new-user-security.evtx", dir.join("Security.evtx")).unwrap();
    }
    assert_cmd::cargo::cargo_bin_cmd!("evtx_dump")
        .args([
            "--canonical",
            "-o",
            "jsonl",
            "--output",
            output.path().to_str().unwrap(),
            input.path().to_str().unwrap(),
        ])
        .assert()
        .success();
    let read = |path: &Path| -> Value {
        let text = std::fs::read_to_string(path).unwrap();
        serde_json::from_str(text.lines().next().unwrap()).unwrap()
    };
    let a = read(&output.path().join("host-a/Security.evtx.jsonl"));
    let b = read(&output.path().join("site/host-b/Security.evtx.jsonl"));
    assert_eq!(a["_teg"]["event_uid"], b["_teg"]["event_uid"]);
    assert_eq!(a["_teg"]["source"]["path"], "host-a/Security.evtx");
    assert_eq!(b["_teg"]["source"]["path"], "site/host-b/Security.evtx");
}

#[test]
fn conflicting_modes_and_output_over_input_are_rejected() {
    assert_cmd::cargo::cargo_bin_cmd!("evtx_dump")
        .args([
            "--canonical",
            "-o",
            "jsonl",
            "--separate-json-attributes",
            "samples/security.evtx",
        ])
        .assert()
        .failure();
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("input.evtx");
    std::fs::copy("samples/new-user-security.evtx", &path).unwrap();
    let before = std::fs::read(&path).unwrap();
    assert_cmd::cargo::cargo_bin_cmd!("evtx_dump")
        .args([
            "--canonical",
            "-o",
            "jsonl",
            "--no-confirm-overwrite",
            "-f",
            path.to_str().unwrap(),
            path.to_str().unwrap(),
        ])
        .assert()
        .failure();
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn xml_evidence_matches_original_renderer_and_offsets_point_to_record_headers() {
    let bytes = std::fs::read("samples/security.evtx").unwrap();
    let mut parser = evtx::EvtxParser::from_buffer(bytes.clone())
        .unwrap()
        .with_configuration(evtx::ParserSettings::default().num_threads(1).indent(false));
    let xml: Vec<_> = parser.records().map(|r| r.unwrap().data).collect();
    let events = export("samples/security.evtx", "4");
    assert_eq!(events.len(), xml.len());
    for (event, original) in events.iter().zip(xml) {
        assert_eq!(event["_teg"]["rendered_xml"], original);
        let offset = event["_teg"]["record"]["offset"].as_u64().unwrap() as usize;
        assert_eq!(&bytes[offset..offset + 4], b"\x2a\x2a\0\0");
        let header_id = u64::from_le_bytes(bytes[offset + 8..offset + 16].try_into().unwrap());
        assert_eq!(event["_teg"]["record"]["record_id"], header_id);
    }
}

#[test]
fn stdin_and_file_have_same_identity_and_acquisition_is_explicit() {
    let file = export("samples/new-user-security.evtx", "1");
    let bytes = std::fs::read("samples/new-user-security.evtx").unwrap();
    let result = assert_cmd::cargo::cargo_bin_cmd!("evtx_dump")
        .args([
            "--canonical",
            "-o",
            "jsonl",
            "--acquired-at",
            "2026-10-01T10:00:00Z",
            "-",
        ])
        .write_stdin(bytes)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdin: Vec<Value> = String::from_utf8(result)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(stdin.len(), file.len());
    for (a, b) in stdin.iter().zip(file) {
        assert_eq!(a["_teg"]["event_uid"], b["_teg"]["event_uid"]);
        assert_eq!(a["_teg"]["acquired_at"], "2026-10-01T10:00:00Z");
    }
}

#[test]
fn physical_offsets_include_skipped_empty_chunks() {
    let mut bytes = std::fs::read("samples/security.evtx").unwrap();
    bytes[4096..4096 + 65536].fill(0);
    let mut reader = std::io::Cursor::new(bytes.clone());
    let source = evtx::canonical::CanonicalSource::from_reader(
        &mut reader,
        "sparse.evtx".into(),
        "2026-10-23T00:00:00Z".parse().unwrap(),
        None,
    )
    .unwrap();
    let mut parser = evtx::EvtxParser::from_read_seek(reader)
        .unwrap()
        .with_configuration(evtx::ParserSettings::default().num_threads(4).indent(false));
    let first = parser.chunks_canonical_json_bytes(source).next().unwrap();
    assert!(!first.items.is_empty());
    assert!(first
        .items
        .iter()
        .all(|i| matches!(i, evtx::RenderedChunkItem::Record { .. })));
    let event: Value =
        serde_json::from_slice(first.data.split(|b| *b == b'\n').next().unwrap()).unwrap();
    let offset = event["_teg"]["record"]["offset"].as_u64().unwrap() as usize;
    assert!(offset >= 4096 + 65536);
    assert_eq!(&bytes[offset..offset + 4], b"\x2a\x2a\0\0");
}

#[test]
fn corrupt_evtx_is_reported_as_failure_instead_of_a_silent_partial_export() {
    let output = assert_cmd::cargo::cargo_bin_cmd!("evtx_dump")
        .args([
            "--canonical",
            "-o",
            "jsonl",
            "-t",
            "1",
            "samples/sysmon.evtx",
        ])
        .assert()
        .failure()
        .get_output()
        .stderr
        .clone();
    assert!(String::from_utf8(output)
        .unwrap()
        .contains("Invalid EVTX chunk header magic"));
}

#[test]
fn invalid_header_reports_source_and_does_not_publish_or_replace_output() {
    let input = tempfile::tempdir().unwrap();
    let output = tempfile::tempdir().unwrap();
    let source = input.path().join("bad-header.evtx");
    let mut bytes = std::fs::read("samples/new-user-security.evtx").unwrap();
    bytes[..8].copy_from_slice(&[0, 0x10, 0, 0, 0x70, 2, 0, 0]);
    std::fs::write(&source, &bytes).unwrap();
    let target = output.path().join("bad-header.evtx.jsonl");
    for previous in [false, true] {
        if previous {
            std::fs::write(&target, b"previous complete export\n").unwrap();
        }
        let stderr = assert_cmd::cargo::cargo_bin_cmd!("evtx_dump")
            .args(["--canonical", "-o", "jsonl", "--no-confirm-overwrite", "-f"])
            .arg(&target)
            .arg(&source)
            .assert()
            .failure()
            .get_output()
            .stderr
            .clone();
        let stderr = String::from_utf8(stderr).unwrap();
        assert!(stderr.contains(source.to_str().unwrap()));
        assert!(stderr.contains("Invalid EVTX file header magic"));
        if previous {
            assert_eq!(
                std::fs::read(&target).unwrap(),
                b"previous complete export\n"
            );
        } else {
            assert!(!target.exists());
        }
        assert_eq!(
            std::fs::read_dir(output.path()).unwrap().count(),
            usize::from(previous)
        );
    }
    let stderr = assert_cmd::cargo::cargo_bin_cmd!("evtx_dump")
        .args(["--canonical", "-o", "jsonl", "--no-confirm-overwrite", "-f"])
        .arg(output.path())
        .arg(input.path())
        .assert()
        .failure()
        .get_output()
        .stderr
        .clone();
    assert!(String::from_utf8(stderr)
        .unwrap()
        .contains(source.to_str().unwrap()));
    assert_eq!(
        std::fs::read(&target).unwrap(),
        b"previous complete export\n"
    );
    assert_eq!(std::fs::read(source).unwrap(), bytes);
}

#[test]
fn failed_later_chunk_discards_partial_output_and_keeps_previous_export() {
    let output = tempfile::tempdir().unwrap();
    for previous in [false, true] {
        let target = output.path().join("sysmon.evtx.jsonl");
        if previous {
            std::fs::write(&target, b"previous complete export\n").unwrap();
        }
        assert_cmd::cargo::cargo_bin_cmd!("evtx_dump")
            .args([
                "--canonical",
                "-o",
                "jsonl",
                "-t",
                "1",
                "--no-confirm-overwrite",
                "-f",
            ])
            .arg(&target)
            .arg("samples/sysmon.evtx")
            .assert()
            .failure();
        if previous {
            assert_eq!(
                std::fs::read(&target).unwrap(),
                b"previous complete export\n"
            );
        } else {
            assert!(!target.exists());
        }
        assert_eq!(
            std::fs::read_dir(output.path()).unwrap().count(),
            usize::from(previous)
        );
    }
}

#[test]
fn directory_omits_empty_logs_and_replaces_complete_named_exports() {
    let input = tempfile::tempdir().unwrap();
    let output = tempfile::tempdir().unwrap();
    let host = input.path().join("host");
    std::fs::create_dir(&host).unwrap();
    std::fs::copy("samples/new-user-security.evtx", host.join("Security.evtx")).unwrap();
    std::fs::copy(
        "samples/Microsoft-Windows-WorkFolders%4WHC.evtx",
        host.join("Empty.evtx"),
    )
    .unwrap();
    let out_host = output.path().join("host");
    std::fs::create_dir(&out_host).unwrap();
    let security = out_host.join("Security.evtx.jsonl");
    let empty = out_host.join("Empty.evtx.jsonl");
    for previous in [false, true] {
        if previous {
            std::fs::write(&security, b"previous complete export\n").unwrap();
            std::fs::write(&empty, b"stale events from an earlier export\n").unwrap();
        }
        let stderr = assert_cmd::cargo::cargo_bin_cmd!("evtx_dump")
            .args(["--canonical", "-o", "jsonl", "--no-confirm-overwrite", "-f"])
            .arg(output.path())
            .arg(input.path())
            .assert()
            .success()
            .get_output()
            .stderr
            .clone();
        assert!(String::from_utf8(stderr)
            .unwrap()
            .contains("No canonical events"));
        assert!(!empty.exists());
        let text = std::fs::read_to_string(&security).unwrap();
        let records: Vec<Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records.len(), 4);
        assert!(records.iter().any(|event| event["EventID"] == 4720));
        assert_eq!(std::fs::read_dir(&out_host).unwrap().count(), 1);
    }
}
