//! Canonical TEG JSONL v1: one record for the graph and Hayabusa's flat JSON importer.
use crate::err::{Result, SerializationError};
use crate::evtx_chunk::RawRecord;
use sha2::{Digest, Sha256};
use sonic_rs::json;
use sonic_rs::{JsonContainerTrait, JsonValueMutTrait, JsonValueTrait, Object, Value};
use std::io::{Read, Seek, SeekFrom};

/// Immutable provenance shared by the bounded, parallel chunk workers.
#[derive(Clone, Debug)]
pub struct CanonicalSource {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub ingested_at: String,
    /// Actual acquisition time, supplied by the examiner; never inferred from export time.
    pub acquired_at: Option<String>,
}

impl CanonicalSource {
    /// Hash the same seekable handle that will be parsed, restoring its position.
    pub fn from_reader<R: Read + Seek>(
        reader: &mut R,
        path: String,
        ingested_at: crate::Timestamp,
        acquired_at: Option<crate::Timestamp>,
    ) -> std::io::Result<Self> {
        let pos = reader.stream_position()?;
        reader.seek(SeekFrom::Start(0))?;
        let mut hash = Sha256::new();
        let mut buf = [0u8; 65536];
        let mut size = 0;
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hash.update(&buf[..n]);
            size += n as u64;
        }
        reader.seek(SeekFrom::Start(pos))?;
        Ok(Self {
            path,
            sha256: format!("{:x}", hash.finalize()),
            size,
            ingested_at: ingested_at.to_string(),
            acquired_at: acquired_at.map(|t| t.to_string()),
        })
    }
}

fn invalid(message: impl Into<String>) -> crate::err::EvtxError {
    SerializationError::JsonStructureError {
        message: message.into(),
    }
    .into()
}

/// Convert inline attributes without invoking the materialized separate-attributes renderer.
/// The XML evidence member is authoritative for ambiguous/repeated/unnamed content.
fn normalize(value: &mut Value) {
    if let Some(values) = value.as_array_mut() {
        values.iter_mut().for_each(normalize);
    } else if let Some(object) = value.as_object_mut() {
        let keys: Vec<_> = object.iter().map(|(key, _)| key.to_owned()).collect();
        for key in keys {
            let Some(child) = object.get_mut(&key) else {
                continue;
            };
            normalize(child);
            let Some(attrs) = child.as_object_mut().and_then(|c| c.remove(&"#attributes")) else {
                continue;
            };
            let attrs_key = format!("{key}_attributes");
            if !object.contains_key(&attrs_key) {
                object.insert(&attrs_key, attrs);
            }
            let child = object.get_mut(&key).unwrap();
            if let Some(c) = child.as_object_mut() {
                if c.is_empty() {
                    object.remove(&key);
                } else if c.len() == 1 && c.contains_key(&"#text") {
                    *child = c.remove(&"#text").unwrap();
                }
            }
        }
    }
}

fn insert_alias(root: &mut Object, key: &str, value: Value) -> Result<()> {
    if let Some(old) = root.get(&key) {
        if old != &value {
            return Err(invalid(format!(
                "Canonical JSONL cannot represent conflicting Hayabusa alias {key:?}; original EVTX is unchanged"
            )));
        }
    } else {
        root.insert(key, value);
    }
    Ok(())
}

// Pinned Hayabusa 4.2.0 eventkey_alias.txt resolves these through System.
// Unaliased names (notably Task) resolve through EventData instead.
fn system_alias(name: &str) -> bool {
    matches!(
        name,
        "Channel"
            | "Computer"
            | "EventID"
            | "Execution_attributes"
            | "Keywords"
            | "Level"
            | "Provider_attributes"
            | "Provider_Name"
            | "SearchFilter"
            | "Security_attributes"
            | "ServerName"
            | "Version"
            | "Hostname"
            | "SourceName"
            | "RecordNumber"
            | "@timestamp"
    )
}

fn project_field(
    root: &mut Object,
    origins: &mut std::collections::BTreeMap<String, String>,
    conflicts: &mut Vec<Value>,
    key: &str,
    value: Value,
    source: &str,
) {
    if source != "System"
        && (matches!(key, "Event" | "_teg")
            || (key == "result" && value.is_object())
            || (key == "rows" && !value.is_null()))
    {
        conflicts.push(json!({"field":key,"selected_source":"envelope",
            "other_source":source,"reason":"reserved importer/envelope key; payload retained in Event"}));
        return;
    }
    if let Some(old) = root.get(&key) {
        if old == &value {
            return;
        }
        let previous = origins.get(key).map(String::as_str).unwrap_or("envelope");
        let choose_system = source == "System" && system_alias(key);
        conflicts.push(json!({"field":key,
            "selected_source":if choose_system { source } else { previous },
            "other_source":if choose_system { previous } else { source },
            "reason":"Hayabusa 4.2.0 alias precedence; both values retained in Event"}));
        if !choose_system {
            return;
        }
    }
    root.insert(key, value);
    origins.insert(key.into(), source.into());
}

/// Hayabusa's native EVTX renderer appends consecutive unnamed Data text into
/// one scalar. Its JSON importer does not perform that normalization itself.
fn payload_alias(key: &str, value: &Value, source: &str, conflicts: &mut Vec<Value>) -> Value {
    if key == "Data"
        && let Some(object) = value.as_object()
        && object.len() == 1
        && let Some(text) = object.get(&"#text")
    {
        let scalar = if text.is_str() {
            Some(text.clone())
        } else if let Some(values) = text.as_array() {
            values
                .iter()
                .map(Value::as_str)
                .collect::<Option<Vec<_>>>()
                .map(|parts| Value::from(&parts.concat()))
        } else {
            None
        };
        if let Some(scalar) = scalar {
            conflicts.push(json!({"field":key,"selected_source":source,
                "other_source":format!("{source}.Data.#text"),
                "reason":"unnamed Data text concatenated for native Hayabusa parity; original values retained in Event"}));
            return scalar;
        }
    }
    value.clone()
}

/// Common Windows records need no owning DOM. Normalize the small System object,
/// borrow payload values, and copy JSON fragments directly into the output envelope.
/// Ambiguous/complex shapes use the checked general projection below.
pub(crate) fn write_record(
    rendered_json: &[u8],
    rendered_xml: &[u8],
    source: &CanonicalSource,
    chunk_index: u64,
    raw: &RawRecord<'_>,
    out: &mut Vec<u8>,
) -> Result<()> {
    let start = out.len();
    if try_write_flat_record(rendered_json, rendered_xml, source, chunk_index, raw, out)
        .unwrap_or(false)
    {
        return Ok(());
    }
    out.truncate(start);
    write_record_owned(rendered_json, rendered_xml, source, chunk_index, raw, out)
}

fn try_write_flat_record(
    input: &[u8],
    xml: &[u8],
    source: &CanonicalSource,
    chunk_index: u64,
    raw: &RawRecord<'_>,
    out: &mut Vec<u8>,
) -> Option<bool> {
    use sonic_rs::{LazyValue, to_object_iter};
    let event = sonic_rs::get(input, ["Event"]).ok()?;
    let event_fields: Vec<_> = to_object_iter(event.as_raw_str())
        .collect::<std::result::Result<_, _>>()
        .ok()?;
    if event_fields
        .iter()
        .any(|(k, _)| !matches!(k.as_ref(), "System" | "EventData" | "#attributes"))
    {
        return None;
    }
    let system = event.get("System")?;
    let data = event.get("EventData");
    let payload: Vec<_> = if let Some(ref data) = data {
        if data.is_null() {
            Vec::new()
        } else if data.is_object() {
            let fields: Vec<_> = to_object_iter(data.as_raw_str())
                .collect::<std::result::Result<_, _>>()
                .ok()?;
            if fields.iter().any(|(_, v)| v.is_object() || v.is_array()) {
                return None;
            }
            fields
        } else {
            return None;
        }
    } else {
        Vec::new()
    };
    // Sibling attribute objects can be emitted straight from the compiled JSON.
    let mut normalized = Vec::with_capacity(512);
    normalized.push(b'{');
    let mut first = true;
    for entry in to_object_iter(system.as_raw_str()) {
        let (key, value) = entry.ok()?;
        if value.is_array() {
            return None;
        }
        let mut content = value.clone();
        let mut emit_value = true;
        if value.is_object() {
            let children: Vec<_> = to_object_iter(value.as_raw_str())
                .collect::<std::result::Result<_, _>>()
                .ok()?;
            if children
                .iter()
                .any(|(k, _)| !matches!(k.as_ref(), "#attributes" | "#text"))
            {
                return None;
            }
            let attrs = value.get("#attributes")?;
            raw_member(
                &mut normalized,
                &mut first,
                &format!("{key}_attributes"),
                attrs.as_raw_str(),
            )
            .ok()?;
            if let Some(text) = value.get("#text") {
                content = text;
            } else {
                emit_value = false;
            }
        }
        if emit_value {
            if key == "EventID" {
                let id = if let Some(n) = content.as_u64() {
                    n
                } else {
                    content.as_str()?.parse::<u64>().ok()?
                };
                raw_member(&mut normalized, &mut first, key.as_ref(), &id.to_string()).ok()?;
            } else {
                raw_member(
                    &mut normalized,
                    &mut first,
                    key.as_ref(),
                    content.as_raw_str(),
                )
                .ok()?;
            }
        }
    }
    normalized.push(b'}');
    let fields: Vec<_> = to_object_iter(normalized.as_slice())
        .collect::<std::result::Result<_, _>>()
        .ok()?;
    if fields
        .iter()
        .enumerate()
        .any(|(i, (key, _))| fields[..i].iter().any(|(other, _)| other == key))
    {
        return None;
    }
    let sys: LazyValue = sonic_rs::from_slice(&normalized).ok()?;
    let time_attrs = sys.get("TimeCreated_attributes")?;
    let event_time = time_attrs.get("SystemTime")?;
    event_time.as_str()?.parse::<crate::Timestamp>().ok()?;
    sys.get("EventID")?.as_u64()?;
    let provider = sys.get("Provider_attributes");
    let null: LazyValue = sonic_rs::from_str("null").ok()?;
    let record_number = raw.event_record_id.to_string();
    let number: LazyValue = sonic_rs::from_str(&record_number).ok()?;
    let aliases = [
        (
            "Hostname",
            sys.get("Computer").unwrap_or_else(|| null.clone()),
        ),
        (
            "SourceName",
            provider
                .as_ref()
                .and_then(|v| v.get("Name"))
                .unwrap_or_else(|| null.clone()),
        ),
        ("RecordNumber", sys.get("EventRecordID").unwrap_or(number)),
        ("@timestamp", event_time.clone()),
    ];
    out.extend_from_slice(b"{\"Event\":{\"System\":");
    out.extend_from_slice(&normalized);
    if let Some(data) = &data {
        out.extend_from_slice(b",\"EventData\":");
        out.extend_from_slice(data.as_raw_str().as_bytes());
    }
    out.push(b'}');
    let mut emitted: Vec<(&str, &str)> = vec![("Event", "reserved"), ("_teg", "reserved")];
    let mut root_first = false;
    for (key, value) in payload.iter().chain(fields.iter()) {
        let name: &str = key.as_ref();
        if name == "rows" && !value.is_null() {
            return None;
        }
        let text = value.as_raw_str();
        if let Some((_, previous)) = emitted.iter().find(|(k, _)| *k == name) {
            if *previous != text {
                return None;
            }
            // Duplicate payload names must use the general last-value projection.
            if payload.iter().filter(|(k, _)| k.as_ref() == name).count() > 1 {
                return None;
            }
        } else {
            raw_member(out, &mut root_first, name, text).ok()?;
            emitted.push((name, text));
        }
    }
    for (name, value) in &aliases {
        let text = value.as_raw_str();
        if let Some((_, previous)) = emitted.iter().find(|(k, _)| k == name) {
            if *previous != text {
                return None;
            }
        } else {
            raw_member(out, &mut root_first, name, text).ok()?;
        }
    }
    append_metadata(
        out,
        xml,
        source,
        chunk_index,
        raw,
        event_time.as_str()?,
        &[],
    )
    .ok()?;
    out.push(b'}');
    Some(true)
}

fn raw_member(out: &mut Vec<u8>, first: &mut bool, name: &str, raw: &str) -> Result<()> {
    if !*first {
        out.push(b',');
    }
    *first = false;
    sonic_rs::to_writer(&mut *out, name).map_err(|e| invalid(e.to_string()))?;
    out.push(b':');
    out.extend_from_slice(raw.as_bytes());
    Ok(())
}

fn append_metadata(
    out: &mut Vec<u8>,
    xml: &[u8],
    source: &CanonicalSource,
    chunk_index: u64,
    raw: &RawRecord<'_>,
    event_time: &str,
    conflicts: &[Value],
) -> Result<()> {
    let offset = 4096 + chunk_index * 65536 + raw.binxml_offset - 24;
    let mut identity = Sha256::new();
    identity.update(b"evtx-teg/v1\0");
    identity.update(source.sha256.as_bytes());
    identity.update(offset.to_le_bytes());
    let xml = std::str::from_utf8(xml).map_err(|_| invalid("Invalid UTF-8 XML evidence"))?;
    out.extend_from_slice(b",\"_teg\":{\"schema\":\"evtx-teg/1.1.0\",\"event_uid\":");
    let write = |out: &mut Vec<u8>, value: &str| {
        sonic_rs::to_writer(out, value).map_err(|e| invalid(e.to_string()))
    };
    write(out, &format!("sha256:{:x}", identity.finalize()))?;
    out.extend_from_slice(b",\"source\":{\"path\":");
    write(out, &source.path)?;
    out.extend_from_slice(b",\"sha256\":");
    write(out, &source.sha256)?;
    use std::io::Write;
    write!(out,",\"size\":{}}},\"record\":{{\"offset\":{},\"record_id\":{},\"recovered\":{}}},\"event_time\":",source.size,offset,raw.event_record_id,raw.recovered)
        .map_err(SerializationError::from)?;
    write(out, event_time)?;
    out.extend_from_slice(b",\"record_header_time\":");
    write(out, &raw.timestamp.to_string())?;
    out.extend_from_slice(b",\"acquired_at\":");
    if let Some(t) = &source.acquired_at {
        write(out, t)?;
    } else {
        out.extend_from_slice(b"null");
    }
    out.extend_from_slice(b",\"ingested_at\":");
    write(out, &source.ingested_at)?;
    out.extend_from_slice(b",\"rendered_xml\":");
    write(out, xml)?;
    out.extend_from_slice(b",\"projection_conflicts\":");
    sonic_rs::to_writer(&mut *out, conflicts).map_err(|e| invalid(e.to_string()))?;
    out.extend_from_slice(b",\"projection\":\"hayabusa-flat-v1; rendered_xml preserves repeated, unnamed and attributed elements\"}");
    Ok(())
}

fn write_record_owned(
    rendered_json: &[u8],
    rendered_xml: &[u8],
    source: &CanonicalSource,
    chunk_index: u64,
    raw: &RawRecord<'_>,
    out: &mut Vec<u8>,
) -> Result<()> {
    let mut value: Value =
        sonic_rs::from_slice(rendered_json).map_err(|e| invalid(e.to_string()))?;
    normalize(&mut value);
    let mut event_value = value
        .as_object_mut()
        .and_then(|v| v.remove(&"Event"))
        .ok_or_else(|| invalid("Expected Event root"))?;
    let event = event_value
        .as_object_mut()
        .ok_or_else(|| invalid("Expected Event object"))?;
    let system = event
        .get_mut(&"System")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| invalid("Expected Event.System object"))?;
    let event_id = system
        .get_mut(&"EventID")
        .ok_or_else(|| invalid("Missing EventID"))?;
    if let Some(text) = event_id.get("#text") {
        *event_id = text.clone();
    }
    if let Some(text) = event_id.as_str() {
        *event_id = Value::from(
            text.parse::<u64>()
                .map_err(|_| invalid("Non-numeric EventID"))?,
        );
    }
    if event_id.as_u64().is_none() {
        return Err(invalid("Non-integer EventID"));
    }
    let event = event_value.as_object().unwrap();
    let system = event.get(&"System").and_then(Value::as_object).unwrap();
    let event_time = system
        .get(&"TimeCreated_attributes")
        .and_then(|v| v.get("SystemTime"))
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Missing TimeCreated SystemTime"))?;
    // Validate but preserve the original precision and spelling for detection parity.
    event_time
        .parse::<crate::Timestamp>()
        .map_err(|_| invalid("Invalid SystemTime"))?;
    let mut root = Object::new();
    let mut origins = std::collections::BTreeMap::new();
    let mut conflicts = Vec::new();
    for container in ["EventData", "UserData"] {
        if let Some(fields) = event.get(&container).and_then(Value::as_object) {
            for (key, val) in fields {
                let alias = payload_alias(key, val, container, &mut conflicts);
                project_field(
                    &mut root,
                    &mut origins,
                    &mut conflicts,
                    key,
                    alias,
                    container,
                );
            }
        }
    }
    for (key, val) in system {
        project_field(
            &mut root,
            &mut origins,
            &mut conflicts,
            key,
            val.clone(),
            "System",
        );
    }
    for (key, val) in [
        (
            "Hostname",
            system
                .get(&"Computer")
                .cloned()
                .unwrap_or(Value::new_null()),
        ),
        (
            "SourceName",
            system
                .get(&"Provider_attributes")
                .and_then(|v| v.get("Name"))
                .cloned()
                .unwrap_or(Value::new_null()),
        ),
        (
            "RecordNumber",
            system
                .get(&"EventRecordID")
                .cloned()
                .unwrap_or(Value::from(raw.event_record_id)),
        ),
        ("@timestamp", Value::from(event_time)),
    ] {
        project_field(&mut root, &mut origins, &mut conflicts, key, val, "System");
    }
    let event_time = event_time.to_owned();
    insert_alias(&mut root, "Event", event_value)?;
    if root.contains_key(&"_teg") {
        return Err(invalid("Reserved _teg payload member"));
    }
    sonic_rs::to_writer(&mut *out, &root).map_err(|e| invalid(e.to_string()))?;
    out.pop();
    append_metadata(
        out,
        rendered_xml,
        source,
        chunk_index,
        raw,
        &event_time,
        &conflicts,
    )?;
    out.push(b'}');
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn borrowed_fast_path_matches_general_projection() {
        let source = CanonicalSource {
            path: "machine/Security.evtx".into(),
            sha256: "a".repeat(64),
            size: 69632,
            ingested_at: "2026-01-01T00:00:00Z".into(),
            acquired_at: None,
        };
        let raw = RawRecord {
            event_record_id: 7,
            timestamp: "2020-01-01T00:00:00Z".parse().unwrap(),
            binxml_offset: 536,
            bytes: &[],
            recovered: false,
        };
        let input = br##"{"Event":{"#attributes":{"xmlns":"test"},"System":{"EventID":{"#attributes":{"Qualifiers":42},"#text":"4720"},"Provider":{"#attributes":{"Name":"Provider","Unknown":"preserved"}},"Computer":"host","Channel":"Security","TimeCreated":{"#attributes":{"SystemTime":"2020-01-01T00:00:00Z"}},"EventRecordID":7},"EventData":{"Name":"a\"b","Number":123,"Empty":"","Null":null}}}"##;
        let mut fast = Vec::new();
        assert_eq!(
            try_write_flat_record(input, b"<Event/>", &source, 0, &raw, &mut fast),
            Some(true)
        );
        let mut general = Vec::new();
        write_record_owned(input, b"<Event/>", &source, 0, &raw, &mut general).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&fast).unwrap(),
            serde_json::from_slice::<serde_json::Value>(&general).unwrap()
        );
    }
    #[test]
    fn separates_attributes_and_event_id_without_losing_unknowns() {
        let mut v = json!({"Event":{"System":{
            "EventID":{"#attributes":{"Qualifiers":42},"#text":4720},
            "Provider":{"#attributes":{"Name":"Security","Unknown":"kept"}},
            "TimeCreated":{"#attributes":{"SystemTime":"2020-01-01T00:00:00Z"}}
        }}});
        normalize(&mut v);
        assert_eq!(v["Event"]["System"]["EventID"], 4720);
        assert_eq!(v["Event"]["System"]["EventID_attributes"]["Qualifiers"], 42);
        assert_eq!(
            v["Event"]["System"]["Provider_attributes"]["Unknown"],
            "kept"
        );
    }

    #[test]
    fn task_payload_wins_and_system_aliases_win_without_losing_either_value() {
        let source = CanonicalSource {
            path: "Application.evtx".into(),
            sha256: "a".repeat(64),
            size: 69632,
            ingested_at: "2026-10-23T00:00:00Z".into(),
            acquired_at: None,
        };
        let raw = RawRecord {
            event_record_id: 7,
            timestamp: "2020-01-01T00:00:00Z".parse().unwrap(),
            binxml_offset: 536,
            bytes: &[],
            recovered: false,
        };
        let input = br##"{"Event":{"System":{"EventID":4720,"Task":1,"Version":1,"TimeCreated":{"#attributes":{"SystemTime":"2020-01-01T00:00:00Z"}}},"EventData":{"Task":"payload-task","Version":"3,3,1,0","EventID":"3036","Data":{"#text":["a","","b"]}}}}"##;
        let mut out = Vec::new();
        write_record(input, b"<Event/>", &source, 0, &raw, &mut out).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["Task"], "payload-task");
        assert_eq!(v["Event"]["System"]["Task"], 1);
        assert_eq!(v["Event"]["EventData"]["Task"], "payload-task");
        assert_eq!(v["Version"], 1);
        assert_eq!(v["EventID"], 4720);
        assert_eq!(v["Event"]["EventData"]["Version"], "3,3,1,0");
        assert_eq!(v["Event"]["EventData"]["EventID"], "3036");
        assert_eq!(v["Data"], "ab");
        assert_eq!(
            v["Event"]["EventData"]["Data"]["#text"],
            serde_json::json!(["a", "", "b"])
        );
        let conflicts = v["_teg"]["projection_conflicts"].as_array().unwrap();
        assert_eq!(conflicts.len(), 4);
        assert!(
            conflicts
                .iter()
                .any(|c| c["field"] == "Task" && c["selected_source"] == "EventData")
        );
        assert!(
            conflicts
                .iter()
                .any(|c| c["field"] == "EventID" && c["selected_source"] == "System")
        );
    }

    #[test]
    fn evidence_preserves_named_repeated_unknown_and_unnamed_elements() {
        let xml = br#"<Event><System><EventID Qualifiers="7">4720</EventID></System><EventData><Data Name="User" Unknown="a">first</Data><Data>unnamed</Data><Data Name="User" Unknown="b">last</Data><Data Name=""></Data></EventData></Event>"#;
        let input = br##"{"Event":{"System":{"EventID":{"#text":"4720","#attributes":{"Qualifiers":7}},"TimeCreated":{"#attributes":{"SystemTime":"2020-01-01T00:00:00Z"}},"Channel":"Security"},"EventData":{"User":"first","User":"last"}}}"##;
        let source = CanonicalSource {
            path: "host/Security.evtx".into(),
            sha256: "a".repeat(64),
            size: 69632,
            ingested_at: "2026-01-01T00:00:00Z".into(),
            acquired_at: None,
        };
        let raw = RawRecord {
            event_record_id: 42,
            timestamp: "2020-01-01T00:00:00Z".parse().unwrap(),
            binxml_offset: 536,
            bytes: &[],
            recovered: false,
        };
        let mut bytes = Vec::new();
        write_record(input, xml, &source, 3, &raw, &mut bytes).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["_teg"]["rendered_xml"], std::str::from_utf8(xml).unwrap());
        assert_eq!(v["Event"]["System"]["EventID"], 4720);
        assert_eq!(v["Event"]["System"]["EventID_attributes"]["Qualifiers"], 7);
        assert_eq!(v["User"], "last");
        assert_eq!(v["_teg"]["record"]["offset"], 4096 + 3 * 65536 + 512);
    }
}
