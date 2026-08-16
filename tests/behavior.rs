mod common;

use std::fs;

use assert_cmd::Command;
use membridge::Error;
use membridge::scan::{ScanReport, ScanSpec, scan};
use membridge::source::{
    Address, CoverageLimitation, MAX_CAPTURED_SEGMENTS, MAX_COVERAGE_LIMITATIONS, MemorySource,
    MinidumpSource, ProcessMemory,
};
use serde_json::{Value, json};
use tempfile::tempdir;
#[cfg(windows)]
const USER_HOME_ENV: &str = "USERPROFILE";
#[cfg(not(windows))]
const USER_HOME_ENV: &str = "HOME";

use common::{
    BASE, BOUNDARY_MATCH, CANARY, FIRST_MATCH, MemoryMetadataFixture, NOACCESS_DECOY,
    SyntheticTarget, TYPED_F32, TYPED_F32_MATCH, TYPED_F64, TYPED_F64_MATCH, TYPED_I64,
    TYPED_I64_MATCH, TYPED_U16_BE, TYPED_U16_BE_MATCH, TYPED_U32, TYPED_U32_MATCH, UTF16_MATCH,
    write_ambiguous_module_fixture, write_coverage_fixture, write_fixture,
    write_oversized_capture_fixture,
};

#[test]
fn minidump_reports_modules_regions_and_partial_coverage() {
    let temp = tempdir().unwrap();
    let dump_path = temp.path().join("fixture.dmp");
    write_fixture(&dump_path);

    let source = MinidumpSource::open(&dump_path).unwrap();
    assert_eq!(source.info().platform, "windows");
    assert_eq!(source.info().architecture, "x86_64");
    assert_eq!(source.info().fingerprint.len(), 64);

    let process = source.open_process("process:0").unwrap();
    assert_eq!(process.regions().len(), 3);
    assert_eq!(process.modules().len(), 1);
    assert!(process.modules()[0].name.ends_with("fixture.exe"));
    assert_eq!(process.modules()[0].base.0, BASE);
    assert_eq!(process.regions()[0].protection, "read | write");
    assert_eq!(process.regions()[0].native_protection, "page_readwrite");
    assert_eq!(process.regions()[1].protection, "none");
    assert_eq!(process.regions()[1].native_protection, "page_noaccess");
    assert_eq!(process.regions()[0].kind, "private");
    assert_eq!(process.regions()[0].captured_bytes, Some(0x2000));

    let coverage = process.coverage();
    assert_eq!(coverage.expected_readable_bytes, 0x3000);
    assert_eq!(coverage.captured_readable_bytes, 0x2000);
    assert_eq!(coverage.unavailable_readable_bytes, 0x1000);
    assert!(coverage.metadata_complete);
    assert!(!coverage.coverage_complete);
    assert_eq!(
        coverage.limitations,
        [CoverageLimitation::KnownReadableBytesMissing]
    );
}

#[test]
fn oversized_captured_segment_count_fails_closed_instead_of_hanging() {
    let temp = tempdir().unwrap();
    let dump_path = temp.path().join("oversized.dmp");
    write_oversized_capture_fixture(&dump_path, MAX_CAPTURED_SEGMENTS + 1);

    let error = MinidumpSource::open(&dump_path).unwrap_err();
    assert_eq!(error.code(), "SOURCE_TOO_LARGE");
    assert!(matches!(error, Error::SourceTooLarge(_)));
}

#[test]
fn coverage_limitations_distinguish_missing_unusable_and_complete_metadata() {
    let temp = tempdir().unwrap();
    let cases = [
        (
            "missing",
            MemoryMetadataFixture::Missing,
            vec![
                CoverageLimitation::MemoryMetadataMissing,
                CoverageLimitation::ExpectedReadableScopeUnproven,
            ],
            false,
        ),
        (
            "unusable",
            MemoryMetadataFixture::Unusable,
            vec![
                CoverageLimitation::MemoryMetadataUnusable,
                CoverageLimitation::ExpectedReadableScopeUnproven,
            ],
            false,
        ),
        ("complete", MemoryMetadataFixture::Complete, vec![], true),
    ];

    for (name, metadata, expected_limitations, expected_complete) in cases {
        let dump_path = temp.path().join(format!("{name}.dmp"));
        write_coverage_fixture(&dump_path, metadata);
        let source = MinidumpSource::open(&dump_path).unwrap();
        let process = source.open_process("process:0").unwrap();
        let coverage = process.coverage();

        assert_eq!(coverage.unavailable_readable_bytes, 0);
        assert_eq!(coverage.coverage_complete, expected_complete);
        assert_eq!(coverage.limitations, expected_limitations);
        assert!(coverage.limitations.len() <= MAX_COVERAGE_LIMITATIONS);
    }

    assert_eq!(MAX_COVERAGE_LIMITATIONS, 6);
}

#[test]
fn exact_scan_finds_boundary_matches_and_skips_noaccess_memory() {
    let temp = tempdir().unwrap();
    let process = fixture_process(&temp.path().join("fixture.dmp"));

    let report = scan(process.as_ref(), &canary_spec(100, None)).unwrap();
    assert!(report.scan_complete);
    assert_eq!(report.terminal_reason, "exhausted_scope");
    assert_eq!(report.matches.len(), 2);
    assert_eq!(report.matches[0].address.0, FIRST_MATCH);
    assert_eq!(report.matches[1].address.0, BOUNDARY_MATCH);
    assert_eq!(report.matches[0].tags, ["canary-a", "canary-b"]);
    assert!(
        report
            .matches
            .iter()
            .all(|found| found.address.0 != NOACCESS_DECOY)
    );
    assert_eq!(
        report.matches[0].module.as_ref().unwrap().rva,
        Address(0x100)
    );

    // An unscoped scan reports no selectors and examines every captured
    // readable byte.
    assert!(report.scope.applied.is_empty());
    assert_eq!(report.scope.interval_count, 0);
    assert_eq!(report.scope.selected_bytes, None);
    assert_eq!(report.scope.scanned_bytes, 0x2000);
}

#[test]
fn match_quota_is_explicit_and_deterministic() {
    let temp = tempdir().unwrap();
    let process = fixture_process(&temp.path().join("fixture.dmp"));

    let report = scan(process.as_ref(), &canary_spec(1, None)).unwrap();
    assert!(!report.scan_complete);
    assert_eq!(report.terminal_reason, "match_limit");
    assert_eq!(report.matches.len(), 1);
    assert_eq!(report.matches[0].address.0, FIRST_MATCH);
    assert_eq!(report.next_address.unwrap().0, BOUNDARY_MATCH);
}

#[test]
fn typed_patterns_encode_width_signedness_and_byte_order() {
    let temp = tempdir().unwrap();
    let process = fixture_process(&temp.path().join("fixture.dmp"));

    let report = scan(
        process.as_ref(),
        &spec(json!({
            "schema": 2,
            "patterns": [
                {"tag": "canary.utf8", "value": {"kind": "utf8", "text": canary_text()}},
                {"tag": "canary.utf16le", "value": {"kind": "utf16le", "text": canary_text()}, "alignment": 2},
                {"tag": "u32.le", "value": {"kind": "int", "number": "0xdeadbeef", "width": 32, "signed": false, "endian": "little"}, "alignment": 4},
                {"tag": "u32.be", "value": {"kind": "int", "number": "0xdeadbeef", "width": 32, "signed": false, "endian": "big"}},
                {"tag": "i64.le", "value": {"kind": "int", "number": "-2", "width": 64, "signed": true, "endian": "little"}, "alignment": 8},
                {"tag": "u16.be", "value": {"kind": "int", "number": "4660", "width": 16, "signed": false, "endian": "big"}},
                {"tag": "f32.le", "value": {"kind": "float", "number": "3.5", "width": 32, "endian": "little"}, "alignment": 4},
                {"tag": "f64.le", "value": {"kind": "float", "number": "-0.5", "width": 64, "endian": "little"}, "alignment": 8}
            ],
            "max_matches": 100
        })),
    )
    .unwrap();

    assert!(report.scan_complete);
    assert_eq!(report.pattern_count, 8);
    let found = report
        .matches
        .iter()
        .map(|found| (found.address.0, found.tags.join(","), found.length))
        .collect::<Vec<_>>();
    assert_eq!(
        found,
        vec![
            (FIRST_MATCH, "canary.utf8".to_owned(), CANARY.len()),
            (TYPED_U32_MATCH, "u32.le".to_owned(), 4),
            (TYPED_I64_MATCH, "i64.le".to_owned(), 8),
            (TYPED_F32_MATCH, "f32.le".to_owned(), 4),
            (TYPED_F64_MATCH, "f64.le".to_owned(), 8),
            (TYPED_U16_BE_MATCH, "u16.be".to_owned(), 2),
            (UTF16_MATCH, "canary.utf16le".to_owned(), CANARY.len() * 2),
            (BOUNDARY_MATCH, "canary.utf8".to_owned(), CANARY.len()),
        ]
    );

    // The fixture plants each value in exactly one byte order, so the
    // big-endian spelling of the little-endian u32 must not be observed.
    assert_eq!(TYPED_U32.to_be_bytes(), [0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(TYPED_I64.to_le_bytes()[0], 0xfe);
    assert_eq!(TYPED_F32.to_le_bytes(), [0x00, 0x00, 0x60, 0x40]);
    assert_eq!(TYPED_F64.to_le_bytes()[7], 0xbf);
    assert_eq!(TYPED_U16_BE.to_be_bytes(), [0x12, 0x34]);
}

#[test]
fn masked_patterns_match_known_bytes_and_nibbles() {
    let temp = tempdir().unwrap();
    let process = fixture_process(&temp.path().join("fixture.dmp"));

    let report = scan(
        process.as_ref(),
        &spec(json!({
            "schema": 2,
            "patterns": [
                {
                    "tag": "canary.bytes-masked",
                    "value": {
                        "kind": "masked",
                        "bytes_hex": "4d42000000004521",
                        "mask_hex": "ffff00000000ffff"
                    }
                },
                {
                    "tag": "canary.nibble-masked",
                    "value": {
                        "kind": "masked",
                        "bytes_hex": "4d42500000004521",
                        "mask_hex": "fffff0000000ffff"
                    }
                }
            ],
            "max_matches": 100
        })),
    )
    .unwrap();

    assert!(report.scan_complete);
    assert_eq!(report.matches.len(), 2);
    assert_eq!(report.matches[0].address.0, FIRST_MATCH);
    assert_eq!(report.matches[1].address.0, BOUNDARY_MATCH);
    for found in &report.matches {
        assert_eq!(found.length, CANARY.len());
        assert_eq!(
            found.tags,
            ["canary.bytes-masked", "canary.nibble-masked"],
            "both masks describe the same eight canary bytes"
        );
    }

    // The UTF-16LE copy of the same text interleaves NUL bytes, so a masked
    // pattern anchored on adjacent ASCII bytes must not reach it.
    assert!(
        report
            .matches
            .iter()
            .all(|found| found.address.0 != UTF16_MATCH)
    );
}

#[test]
fn typed_and_masked_specifications_reject_ambiguous_input() {
    let temp = tempdir().unwrap();
    let process = fixture_process(&temp.path().join("fixture.dmp"));

    let cases: [(&str, Value); 9] = [
        (
            "schema",
            json!({"schema": 1, "patterns": [{"tag": "a", "value": {"kind": "utf8", "text": "x"}}]}),
        ),
        (
            "int width",
            json!({"schema": 2, "patterns": [{"tag": "a", "value": {"kind": "int", "number": "1", "width": 24, "signed": false, "endian": "little"}}]}),
        ),
        (
            "unsigned range",
            json!({"schema": 2, "patterns": [{"tag": "a", "value": {"kind": "int", "number": "256", "width": 8, "signed": false, "endian": "little"}}]}),
        ),
        (
            "signed range",
            json!({"schema": 2, "patterns": [{"tag": "a", "value": {"kind": "int", "number": "128", "width": 8, "signed": true, "endian": "little"}}]}),
        ),
        (
            "unsigned negative",
            json!({"schema": 2, "patterns": [{"tag": "a", "value": {"kind": "int", "number": "-1", "width": 32, "signed": false, "endian": "little"}}]}),
        ),
        (
            "float nan",
            json!({"schema": 2, "patterns": [{"tag": "a", "value": {"kind": "float", "number": "NaN", "width": 32, "endian": "little"}}]}),
        ),
        (
            "empty text",
            json!({"schema": 2, "patterns": [{"tag": "a", "value": {"kind": "utf8", "text": ""}}]}),
        ),
        (
            "mask length",
            json!({"schema": 2, "patterns": [{"tag": "a", "value": {"kind": "masked", "bytes_hex": "4d42", "mask_hex": "ff"}}]}),
        ),
        (
            "mask has no known byte",
            json!({"schema": 2, "patterns": [{"tag": "a", "value": {"kind": "masked", "bytes_hex": "4040", "mask_hex": "f0f0"}}]}),
        ),
    ];

    for (name, value) in cases {
        let error = scan(process.as_ref(), &spec(value)).unwrap_err();
        assert_eq!(error.code(), "INVALID_SCAN_SPEC", "case {name}");
    }

    // Value bits outside the mask are rejected instead of being silently
    // cleared, so a mask and its value can never disagree.
    let error = scan(
        process.as_ref(),
        &spec(json!({
            "schema": 2,
            "patterns": [{"tag": "a", "value": {"kind": "masked", "bytes_hex": "4d42", "mask_hex": "ff00"}}]
        })),
    )
    .unwrap_err();
    assert_eq!(error.code(), "INVALID_SCAN_SPEC");
    assert!(error.to_string().contains("outside its mask"));

    // Unknown pattern kinds and unknown fields fail at deserialization.
    assert!(
        serde_json::from_value::<ScanSpec>(json!({
            "schema": 2,
            "patterns": [{"tag": "a", "value": {"kind": "utf32", "text": "x"}}]
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<ScanSpec>(json!({
            "schema": 2,
            "patterns": [{"tag": "a", "value": {"kind": "utf8", "text": "x", "encoding": "utf8"}}]
        }))
        .is_err()
    );
}

#[test]
fn scope_selectors_intersect_deterministically() {
    let temp = tempdir().unwrap();
    let process = fixture_process(&temp.path().join("fixture.dmp"));

    let module = scan(
        process.as_ref(),
        &canary_spec(100, Some(json!({"modules": ["fixture.exe"]}))),
    )
    .unwrap();
    assert_eq!(module.scope.applied, ["modules"]);
    assert_eq!(module.scope.interval_count, 1);
    assert_eq!(module.scope.selected_bytes, Some(0x2000));
    assert_eq!(module.scope.scanned_bytes, 0x2000);
    assert_eq!(addresses(&module), vec![FIRST_MATCH, BOUNDARY_MATCH]);

    // The full image path selects the same module.
    let path = scan(
        process.as_ref(),
        &canary_spec(100, Some(json!({"modules": [r"C:\dev\fixture.exe"]}))),
    )
    .unwrap();
    assert_eq!(addresses(&path), vec![FIRST_MATCH, BOUNDARY_MATCH]);

    // Region 0 holds both canaries; region 2 is readable but was never captured.
    let captured_region = scan(
        process.as_ref(),
        &canary_spec(100, Some(json!({"regions": [0]}))),
    )
    .unwrap();
    assert_eq!(
        addresses(&captured_region),
        vec![FIRST_MATCH, BOUNDARY_MATCH]
    );
    let missing_region = scan(
        process.as_ref(),
        &canary_spec(100, Some(json!({"regions": [2]}))),
    )
    .unwrap();
    assert!(missing_region.scan_complete);
    assert!(addresses(&missing_region).is_empty());
    assert_eq!(missing_region.scope.selected_bytes, Some(0x1000));
    assert_eq!(missing_region.scope.scanned_bytes, 0);

    // The boundary canary starts at 0xffc, so a range beginning at 0x1000
    // covers only part of it and must not report a match.
    let partial_range = scan(
        process.as_ref(),
        &canary_spec(
            100,
            Some(json!({"ranges": [{"start": "0x140001000", "length": "0x1000"}]})),
        ),
    )
    .unwrap();
    assert!(partial_range.scan_complete);
    assert!(addresses(&partial_range).is_empty());
    assert_eq!(partial_range.scope.scanned_bytes, 0x1000);

    // Overlapping ranges merge, so neither match is duplicated or dropped.
    let overlapping = scan(
        process.as_ref(),
        &canary_spec(
            100,
            Some(json!({"ranges": [
                {"start": "0x140000000", "length": "0x1000"},
                {"start": "0x140000800", "length": "0x1000"}
            ]})),
        ),
    )
    .unwrap();
    assert_eq!(overlapping.scope.interval_count, 1);
    assert_eq!(overlapping.scope.selected_bytes, Some(0x1800));
    assert_eq!(addresses(&overlapping), vec![FIRST_MATCH, BOUNDARY_MATCH]);

    // Categories intersect: the module range narrowed to its first 0x200 bytes.
    let intersection = scan(
        process.as_ref(),
        &canary_spec(
            100,
            Some(json!({
                "modules": ["fixture.exe"],
                "ranges": [{"start": "0x140000000", "length": "0x200"}]
            })),
        ),
    )
    .unwrap();
    assert_eq!(intersection.scope.applied, ["modules", "ranges"]);
    assert_eq!(intersection.scope.selected_bytes, Some(0x200));
    assert_eq!(addresses(&intersection), vec![FIRST_MATCH]);

    // Metadata-backed classes select whole regions. Selectors name portable access
    // rights, so one selector spans every native protection carrying that right.
    let writable = scan(
        process.as_ref(),
        &canary_spec(100, Some(json!({"protections": ["write"]}))),
    )
    .unwrap();
    assert_eq!(writable.scope.selected_bytes, Some(0x3000));
    assert_eq!(addresses(&writable), vec![FIRST_MATCH, BOUNDARY_MATCH]);
    let executable = scan(
        process.as_ref(),
        &canary_spec(100, Some(json!({"protections": ["execute"]}))),
    )
    .unwrap();
    assert_eq!(executable.scope.selected_bytes, Some(0));
    assert!(addresses(&executable).is_empty());
    let private = scan(
        process.as_ref(),
        &canary_spec(100, Some(json!({"types": ["private"]}))),
    )
    .unwrap();
    assert_eq!(addresses(&private), vec![FIRST_MATCH, BOUNDARY_MATCH]);
    let image = scan(
        process.as_ref(),
        &canary_spec(100, Some(json!({"types": ["image"]}))),
    )
    .unwrap();
    assert!(addresses(&image).is_empty());
}

#[test]
fn scoped_match_limit_resumes_in_scope_order() {
    let temp = tempdir().unwrap();
    let process = fixture_process(&temp.path().join("fixture.dmp"));

    let report = scan(
        process.as_ref(),
        &canary_spec(1, Some(json!({"modules": ["fixture.exe"]}))),
    )
    .unwrap();
    assert!(!report.scan_complete);
    assert_eq!(report.terminal_reason, "match_limit");
    assert_eq!(addresses(&report), vec![FIRST_MATCH]);
    assert_eq!(report.next_address.unwrap().0, BOUNDARY_MATCH);
}

#[test]
fn unresolvable_scopes_fail_with_stable_codes() {
    let temp = tempdir().unwrap();
    let process = fixture_process(&temp.path().join("fixture.dmp"));

    let cases: [(&str, Value, &str); 7] = [
        (
            "unknown module",
            json!({"modules": ["absent.dll"]}),
            "UNRESOLVED_SCOPE",
        ),
        (
            "unknown region",
            json!({"regions": [9]}),
            "UNRESOLVED_SCOPE",
        ),
        (
            "unknown protection",
            json!({"protections": ["page_readwriteish"]}),
            "INVALID_SCAN_SPEC",
        ),
        (
            "unknown type",
            json!({"types": ["stack"]}),
            "INVALID_SCAN_SPEC",
        ),
        (
            "empty category",
            json!({"modules": []}),
            "INVALID_SCAN_SPEC",
        ),
        ("empty scope", json!({}), "INVALID_SCAN_SPEC"),
        (
            "zero-length range",
            json!({"ranges": [{"start": "0x140000000", "length": "0"}]}),
            "INVALID_SCAN_SPEC",
        ),
    ];

    for (name, scope, code) in cases {
        let error = scan(process.as_ref(), &canary_spec(100, Some(scope))).unwrap_err();
        assert_eq!(error.code(), code, "case {name}");
    }

    // Protection and type classes require region metadata; a dump without it
    // fails explicitly instead of scanning an unproven scope.
    let without_metadata = temp.path().join("missing.dmp");
    write_coverage_fixture(&without_metadata, MemoryMetadataFixture::Missing);
    let bare = MinidumpSource::open(&without_metadata)
        .unwrap()
        .open_process("process:0")
        .unwrap();
    for scope in [
        json!({"protections": ["page_readwrite"]}),
        json!({"types": ["private"]}),
    ] {
        let error = scan(bare.as_ref(), &canary_spec(100, Some(scope))).unwrap_err();
        assert_eq!(error.code(), "SCOPE_METADATA_UNAVAILABLE");
        assert!(matches!(error, Error::ScopeMetadataUnavailable(_)));
    }

    // A file name shared by two captured modules is ambiguous; the full path
    // still resolves.
    let ambiguous_path = temp.path().join("ambiguous.dmp");
    write_ambiguous_module_fixture(&ambiguous_path);
    let ambiguous = MinidumpSource::open(&ambiguous_path)
        .unwrap()
        .open_process("process:0")
        .unwrap();
    let error = scan(
        ambiguous.as_ref(),
        &canary_spec(100, Some(json!({"modules": ["fixture.exe"]}))),
    )
    .unwrap_err();
    assert_eq!(error.code(), "UNRESOLVED_SCOPE");
    assert!(error.to_string().contains("matches 2 captured modules"));
    let resolved = scan(
        ambiguous.as_ref(),
        &canary_spec(100, Some(json!({"modules": [r"C:\other\fixture.exe"]}))),
    )
    .unwrap();
    assert_eq!(resolved.scope.selected_bytes, Some(0x1000));
    assert!(addresses(&resolved).is_empty());
}

#[test]
fn bounded_read_reports_gaps_without_fabricating_bytes() {
    let temp = tempdir().unwrap();
    let dump_path = temp.path().join("fixture.dmp");
    write_fixture(&dump_path);
    let source = MinidumpSource::open(&dump_path).unwrap();
    let process = source.open_process("process:0").unwrap();

    let segments = process.read(BASE + 0x2ff0, 0x20).unwrap();
    assert_eq!(segments.len(), 1);
    assert_eq!(segments[0].address, BASE + 0x2ff0);
    assert_eq!(segments[0].bytes.len(), 0x10);
}

#[test]
fn cli_emits_one_compact_json_object_per_command() {
    let temp = tempdir().unwrap();
    let dump_path = temp.path().join("fixture.dmp");
    let spec_path = temp.path().join("scan.json");
    write_fixture(&dump_path);
    fs::write(
        &spec_path,
        serde_json::to_vec(&json!({
            "schema": 2,
            "patterns": [
                {"tag": "canary.utf8", "value": {"kind": "utf8", "text": canary_text()}},
                {
                    "tag": "canary.utf16le",
                    "value": {"kind": "utf16le", "text": canary_text()},
                    "alignment": 2
                }
            ],
            "scope": {"modules": ["fixture.exe"]},
            "max_matches": 10
        }))
        .unwrap(),
    )
    .unwrap();

    let inspect = Command::cargo_bin("membridge")
        .unwrap()
        .arg("inspect")
        .arg(&dump_path)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let inspect: Value = serde_json::from_slice(&inspect).unwrap();
    assert_eq!(inspect["schema"], 4);
    assert_eq!(inspect["ok"], true);
    assert_eq!(inspect["command"], "inspect");
    assert_eq!(inspect["data"]["coverage"]["coverage_complete"], false);
    assert_eq!(
        inspect["data"]["coverage"]["limitations"],
        serde_json::json!(["KNOWN_READABLE_BYTES_MISSING"])
    );

    let scan = Command::cargo_bin("membridge")
        .unwrap()
        .arg("scan")
        .arg(&dump_path)
        .arg("--spec")
        .arg(&spec_path)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let scan: Value = serde_json::from_slice(&scan).unwrap();
    assert_eq!(
        scan["data"]["report"]["matches"].as_array().unwrap().len(),
        3
    );
    assert_eq!(
        scan["data"]["report"]["matches"][0]["address"],
        "0x0000000140000100"
    );
    assert_eq!(
        scan["data"]["report"]["matches"][0]["region"]["protection"],
        "read | write"
    );
    assert_eq!(
        scan["data"]["report"]["matches"][0]["region"]["native_protection"],
        "page_readwrite"
    );
    assert_eq!(
        scan["data"]["report"]["matches"][1]["tags"],
        json!(["canary.utf16le"])
    );
    assert_eq!(
        scan["data"]["report"]["matches"][2]["address"],
        "0x0000000140000ffc"
    );
    assert_eq!(
        scan["data"]["report"]["scope"],
        json!({
            "applied": ["modules"],
            "interval_count": 1,
            "selected_bytes": 8192,
            "scanned_bytes": 8192
        })
    );
    assert_eq!(
        scan["data"]["report"]["coverage"]["limitations"],
        inspect["data"]["coverage"]["limitations"]
    );

    let read = Command::cargo_bin("membridge")
        .unwrap()
        .arg("read")
        .arg(&dump_path)
        .arg("--address")
        .arg(format!("0x{FIRST_MATCH:x}"))
        .arg("--length")
        .arg(CANARY.len().to_string())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let read: Value = serde_json::from_slice(&read).unwrap();
    assert_eq!(
        read["data"]["segments"][0]["bytes_hex"],
        hex::encode(CANARY)
    );
    assert_eq!(read["data"]["complete"], true);
}

#[test]
fn cli_reports_every_specification_problem_as_one_stable_code() {
    let temp = tempdir().unwrap();
    let dump_path = temp.path().join("fixture.dmp");
    write_fixture(&dump_path);

    for body in [
        "{ not json",
        r#"{"schema": 2, "patterns": [{"tag": "a", "value": {"kind": "utf32", "text": "x"}}]}"#,
        r#"{"schema": 2, "patterns": [{"tag": "a", "value": {"kind": "utf8", "text": "x"}}], "scope": {"regions": [9]}}"#,
    ] {
        let spec_path = temp.path().join("scan.json");
        fs::write(&spec_path, body).unwrap();
        let failure = Command::cargo_bin("membridge")
            .unwrap()
            .arg("scan")
            .arg(&dump_path)
            .arg("--spec")
            .arg(&spec_path)
            .assert()
            .failure()
            .get_output()
            .stdout
            .clone();
        let failure: Value = serde_json::from_slice(&failure).unwrap();
        assert_eq!(failure["schema"], 4);
        assert_eq!(failure["command"], "scan");
        let code = failure["error"]["code"].as_str().unwrap();
        assert!(
            matches!(code, "INVALID_SCAN_SPEC" | "UNRESOLVED_SCOPE"),
            "unexpected code {code} for {body}"
        );
    }
}

#[test]
fn cli_installs_the_version_matched_agent_skill() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("home");
    let destination = home.join(".agents").join("skills").join("membridge");

    let installed = Command::cargo_bin("membridge")
        .unwrap()
        .args(["skill", "install"])
        .env(USER_HOME_ENV, &home)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let installed: Value = serde_json::from_slice(&installed).unwrap();
    assert_eq!(installed["command"], "skill.install");
    assert_eq!(
        installed["data"]["destination"],
        destination.to_string_lossy().as_ref()
    );
    assert_eq!(installed["data"]["replaced"], false);
    assert_eq!(
        installed["data"]["binary_version"],
        env!("CARGO_PKG_VERSION")
    );
    assert_eq!(
        installed["data"]["skill_version"],
        env!("CARGO_PKG_VERSION")
    );
    assert_eq!(
        installed["data"]["files"],
        serde_json::json!([
            "SKILL.md",
            "examples/canary-batch.json",
            "examples/scoped-batch.json",
            "examples/live-batch.json",
            "scripts/install.sh",
            "scripts/install.ps1"
        ])
    );

    let installed_skill = fs::read_to_string(destination.join("SKILL.md")).unwrap();
    assert_eq!(
        installed_skill,
        include_str!("../.agents/skills/membridge/SKILL.md")
    );
    let installed_example =
        fs::read_to_string(destination.join("examples").join("canary-batch.json")).unwrap();
    assert_eq!(
        installed_example,
        include_str!("../.agents/skills/membridge/examples/canary-batch.json")
    );
    let installed_scoped =
        fs::read_to_string(destination.join("examples").join("scoped-batch.json")).unwrap();
    assert_eq!(
        installed_scoped,
        include_str!("../.agents/skills/membridge/examples/scoped-batch.json")
    );
    let installed_live =
        fs::read_to_string(destination.join("examples").join("live-batch.json")).unwrap();
    assert_eq!(
        installed_live,
        include_str!("../.agents/skills/membridge/examples/live-batch.json")
    );
    let installed_shell =
        fs::read_to_string(destination.join("scripts").join("install.sh")).unwrap();
    assert_eq!(
        installed_shell,
        include_str!("../.agents/skills/membridge/scripts/install.sh")
    );
    let installed_powershell =
        fs::read_to_string(destination.join("scripts").join("install.ps1")).unwrap();
    assert_eq!(
        installed_powershell,
        include_str!("../.agents/skills/membridge/scripts/install.ps1")
    );
    // The embedded bootstrap scripts pin the latest *published* release, which
    // can lag behind this crate's own version between a bump and actually
    // cutting that release (see AGENTS.md). Assert each script is internally
    // self-consistent - its declared version and its download URL agree -
    // rather than hardcoding a version literal here that would silently drift.
    let shell_version = installed_shell
        .lines()
        .find_map(|line| {
            line.strip_prefix("VERSION=\"")
                .and_then(|rest| rest.strip_suffix('"'))
        })
        .expect("install.sh declares VERSION=\"...\"");
    assert!(installed_shell.contains(&format!("releases/download/v{shell_version}/")));
    let powershell_version = installed_powershell
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("$Version = '")
                .and_then(|rest| rest.strip_suffix('\''))
        })
        .expect("install.ps1 declares $Version = '...'");
    assert!(installed_powershell.contains(&format!("releases/download/v{powershell_version}/")));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = fs::metadata(destination.join("scripts").join("install.sh"))
            .unwrap()
            .permissions()
            .mode();
        assert_ne!(mode & 0o111, 0);
    }

    let replaced = Command::cargo_bin("membridge")
        .unwrap()
        .args(["skill", "install", "--force"])
        .env(USER_HOME_ENV, &home)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let replaced: Value = serde_json::from_slice(&replaced).unwrap();
    assert_eq!(replaced["data"]["replaced"], true);
    let skills_root = destination.parent().unwrap();
    let entries: Vec<_> = fs::read_dir(skills_root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(entries, vec![std::ffi::OsString::from("membridge")]);
}

#[cfg(unix)]
#[test]
fn shell_bootstrap_skips_a_match_and_rejects_a_tampered_installer() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempdir().unwrap();
    let fake_bin = temp.path().join("bin");
    fs::create_dir(&fake_bin).unwrap();
    let fake_curl = fake_bin.join("curl");
    fs::write(
        &fake_curl,
        r#"#!/bin/sh
output=
while [ "$#" -gt 0 ]; do
    if [ "$1" = "--output" ]; then
        output=$2
        shift 2
    else
        shift
    fi
done
printf tampered > "$output"
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&fake_curl).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&fake_curl, permissions).unwrap();
    // The bootstrap script pins its own "already installed" version
    // independent of this crate's `CARGO_PKG_VERSION` (see AGENTS.md); read it
    // from the real script instead of hardcoding a literal that would drift.
    let bootstrap = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(".agents/skills/membridge/scripts/install.sh");
    let bootstrap_source = fs::read_to_string(&bootstrap).unwrap();
    let pinned_version = bootstrap_source
        .lines()
        .find_map(|line| {
            line.strip_prefix("VERSION=\"")
                .and_then(|rest| rest.strip_suffix('"'))
        })
        .expect("install.sh declares VERSION=\"...\"");
    let fake_membridge = fake_bin.join("membridge");
    fs::write(
        &fake_membridge,
        format!("#!/bin/sh\nprintf 'membridge {pinned_version}\\n'\n"),
    )
    .unwrap();
    let mut permissions = fs::metadata(&fake_membridge).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&fake_membridge, permissions).unwrap();

    let path = format!("{}:/usr/bin:/bin:/usr/sbin:/sbin", fake_bin.display());
    let skipped = std::process::Command::new("sh")
        .arg(&bootstrap)
        .env("PATH", &path)
        .env("CARGO_HOME", temp.path().join("cargo"))
        .output()
        .unwrap();
    assert!(skipped.status.success());
    assert!(String::from_utf8_lossy(&skipped.stdout).contains("is already installed"));

    let output = std::process::Command::new("sh")
        .arg(bootstrap)
        .env("PATH", &path)
        .env("CARGO_HOME", temp.path().join("cargo"))
        .env("MEMBRIDGE_BOOTSTRAP_FORCE", "1")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("release installer checksum mismatch")
    );
}

#[cfg(windows)]
#[test]
fn powershell_bootstrap_skips_a_matching_binary_without_network() {
    let temp = tempdir().unwrap();
    let fake_bin = temp.path().join("bin");
    fs::create_dir(&fake_bin).unwrap();

    let bootstrap = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(".agents/skills/membridge/scripts/install.ps1");
    // The bootstrap script pins its own "already installed" version
    // independent of this crate's `CARGO_PKG_VERSION` (see AGENTS.md); read it
    // from the real script instead of hardcoding a literal that would drift.
    let bootstrap_source = fs::read_to_string(&bootstrap).unwrap();
    let pinned_version = bootstrap_source
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("$Version = '")
                .and_then(|rest| rest.strip_suffix('\''))
        })
        .expect("install.ps1 declares $Version = '...'");
    fs::write(
        fake_bin.join("membridge.cmd"),
        format!("@echo off\r\necho membridge {pinned_version}\r\n"),
    )
    .unwrap();

    let inherited_path = std::env::var_os("PATH").unwrap();
    let path = std::env::join_paths(
        std::iter::once(fake_bin.clone()).chain(std::env::split_paths(&inherited_path)),
    )
    .unwrap();
    let powershell = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap())
        .join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let output = std::process::Command::new(powershell)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(bootstrap)
        .env("PATH", path)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("is already installed"));
}

#[test]
fn cli_help_and_version_flags_exit_successfully() {
    let version = Command::cargo_bin("membridge")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(
        String::from_utf8(version).unwrap(),
        format!("membridge {}\n", env!("CARGO_PKG_VERSION"))
    );

    let help = Command::cargo_bin("membridge")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let help = String::from_utf8(help).unwrap();
    assert!(help.contains("Usage:"));
    assert!(help.contains("<COMMAND>"));
    assert!(help.contains("Commands:"));
}

#[test]
fn cli_rejects_obsolete_skill_destination_flags() {
    for arguments in [
        vec!["skill", "install", "--omp"],
        vec!["skill", "install", "--target", "skills"],
    ] {
        let failure = Command::cargo_bin("membridge")
            .unwrap()
            .args(arguments)
            .assert()
            .failure()
            .code(2)
            .get_output()
            .stdout
            .clone();
        let failure: Value = serde_json::from_slice(&failure).unwrap();
        assert_eq!(failure["command"], "cli");
        assert_eq!(failure["error"]["code"], "INVALID_ARGUMENT");
    }
}

#[test]
fn cli_rejects_unavailable_or_relative_user_home() {
    let mut missing = Command::cargo_bin("membridge").unwrap();
    missing.env_remove("HOME");
    #[cfg(windows)]
    missing.env_remove("USERPROFILE");
    let missing = missing
        .args(["skill", "install"])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let missing: Value = serde_json::from_slice(&missing).unwrap();
    assert_eq!(missing["command"], "skill.install");
    assert_eq!(missing["error"]["code"], "HOME_DIRECTORY_UNAVAILABLE");

    let relative = Command::cargo_bin("membridge")
        .unwrap()
        .args(["skill", "install"])
        .env(USER_HOME_ENV, "relative/home")
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let relative: Value = serde_json::from_slice(&relative).unwrap();
    assert_eq!(relative["error"]["code"], "HOME_DIRECTORY_UNAVAILABLE");
    assert!(
        relative["error"]["message"]
            .as_str()
            .unwrap()
            .contains("not absolute")
    );
}

#[test]
fn portable_marketplace_exposes_the_canonical_versioned_skill() {
    let catalog: Value =
        serde_json::from_str(include_str!("../.claude-plugin/marketplace.json")).unwrap();
    assert_eq!(catalog["name"], "membridge");
    // The package ships the skill for one binary and is version-matched to it, so the
    // catalog carries that binary's version and nothing else.
    let plugin_version = env!("CARGO_PKG_VERSION");
    assert_eq!(catalog["metadata"]["version"], plugin_version);

    let plugin = &catalog["plugins"][0];
    assert_eq!(plugin["name"], "membridge");
    assert_eq!(plugin["version"], plugin_version);
    assert_eq!(plugin["source"], "./.agents");
    assert_eq!(catalog["plugins"].as_array().unwrap().len(), 1);

    let source = plugin["source"].as_str().unwrap();
    let plugin_root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(source.strip_prefix("./").unwrap());
    let marketplace_skill =
        fs::read_to_string(plugin_root.join("skills/membridge/SKILL.md")).unwrap();
    assert_eq!(
        marketplace_skill,
        include_str!("../.agents/skills/membridge/SKILL.md")
    );
}

#[cfg(not(windows))]
#[test]
fn capture_minidump_reports_unsupported_host_off_windows() {
    let temp = tempdir().unwrap();
    let output_path = temp.path().join("capture.dmp");

    let failure = Command::cargo_bin("membridge")
        .unwrap()
        .args(["capture", "minidump", "--pid"])
        .arg(std::process::id().to_string())
        .arg("--output")
        .arg(&output_path)
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let failure: Value = serde_json::from_slice(&failure).unwrap();
    assert_eq!(failure["command"], "capture.minidump");
    assert_eq!(failure["error"]["code"], "UNSUPPORTED_HOST");
    assert!(!output_path.exists());
}

#[cfg(windows)]
#[test]
fn capture_minidump_writes_an_analyzable_dump_from_a_live_process() {
    let temp = tempdir().unwrap();
    let output_path = temp.path().join("capture.dmp");

    let target = SyntheticTarget::start();
    let readable_address = target.readable;

    let before_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let captured = Command::cargo_bin("membridge")
        .unwrap()
        .args(["capture", "minidump", "--pid"])
        .arg(target.pid.to_string())
        .arg("--output")
        .arg(&output_path)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let captured: Value = serde_json::from_slice(&captured).unwrap();
    assert_eq!(captured["command"], "capture.minidump");
    assert_eq!(captured["schema"], 4);
    let data = &captured["data"];
    assert_eq!(
        data["process"]["pid"].as_u64().unwrap(),
        u64::from(target.pid)
    );
    assert!(
        data["process"]["image_path"]
            .as_str()
            .unwrap()
            .to_ascii_lowercase()
            .contains("synthetic-target")
    );
    assert!(data["process"]["creation_time_unix_ms"].as_u64().unwrap() <= before_unix_ms);
    let started = data["interval"]["started_at_unix_ms"].as_u64().unwrap();
    let completed = data["interval"]["completed_at_unix_ms"].as_u64().unwrap();
    assert!(started >= before_unix_ms);
    assert!(completed >= started);
    assert_eq!(
        data["flags"],
        serde_json::json!([
            "MiniDumpWithFullMemory",
            "MiniDumpWithFullMemoryInfo",
            "MiniDumpWithThreadInfo",
            "MiniDumpWithProcessThreadData",
            "MiniDumpWithUnloadedModules",
            "MiniDumpIgnoreInaccessibleMemory"
        ])
    );
    assert_eq!(data["warnings"], serde_json::json!([]));
    assert_eq!(data["output"], output_path.to_string_lossy().as_ref());
    assert_eq!(data["source"]["platform"], "windows");
    assert_eq!(data["source"]["architecture"], "x86_64");

    let conflict = Command::cargo_bin("membridge")
        .unwrap()
        .args(["capture", "minidump", "--pid"])
        .arg(target.pid.to_string())
        .arg("--output")
        .arg(&output_path)
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let conflict: Value = serde_json::from_slice(&conflict).unwrap();
    assert_eq!(conflict["error"]["code"], "INVALID_ARGUMENT");

    Command::cargo_bin("membridge")
        .unwrap()
        .args(["capture", "minidump", "--pid"])
        .arg(target.pid.to_string())
        .arg("--output")
        .arg(&output_path)
        .arg("--force")
        .assert()
        .success();

    drop(target);

    let source = MinidumpSource::open(&output_path).unwrap();
    assert_eq!(source.info().platform, "windows");
    let process = source.open_process(&source.processes()[0].id).unwrap();
    assert!(process.coverage().captured_readable_bytes > 0);

    let scan_spec = spec(json!({
        "schema": 2,
        "patterns": [{
            "tag": "capture-canary",
            "value": {"kind": "utf8", "text": "MBRIDGE-CAPTURE-READABLE!!"}
        }],
        "max_matches": 10
    }));
    let report = scan(process.as_ref(), &scan_spec).unwrap();
    // The canary is a `const` in the target binary, so it may also appear
    // once in the target's own loaded module image (rodata) in addition to
    // the VirtualAlloc'd page written at runtime; assert the specific page we
    // set up is found, not an exact incidental total.
    assert!(!report.matches.is_empty());
    assert!(
        report
            .matches
            .iter()
            .any(|found| found.address.0 == readable_address)
    );
}

/// The contract that makes chunked live scanning trustworthy: a pattern straddling a
/// chunk boundary is found, and the repeated overlap bytes never report it twice.
#[test]
fn chunked_spans_find_boundary_patterns_exactly_once() {
    const BASE: u64 = 0x0000_0002_0000_0000;
    const CHUNK: usize = 4096;

    let mut bytes = vec![0_u8; CHUNK * 3];
    // Straddles the first chunk boundary: 4 bytes before it, 4 after.
    bytes[CHUNK - 4..CHUNK + 4].copy_from_slice(b"STRADDLE");
    // Sits wholly inside the bytes the second chunk repeats as its carry, so a naive
    // implementation that rescans the overlap would report it twice.
    bytes[CHUNK - 16..CHUNK - 8].copy_from_slice(b"INCARRY!");
    // Sits wholly inside the second chunk, clear of every overlap.
    bytes[CHUNK + 64..CHUNK + 72].copy_from_slice(b"INTERIOR");

    let process = common::ChunkedSource::new(BASE, bytes, CHUNK);
    let report = scan(
        &process,
        &spec(json!({
            "schema": 2,
            "patterns": [
                {"tag": "straddle", "value": {"kind": "utf8", "text": "STRADDLE"}},
                {"tag": "carry", "value": {"kind": "utf8", "text": "INCARRY!"}},
                {"tag": "interior", "value": {"kind": "utf8", "text": "INTERIOR"}}
            ],
            "max_matches": 100
        })),
    )
    .unwrap();

    assert_eq!(
        report
            .matches
            .iter()
            .map(|found| (found.address.0 - BASE, found.tags[0].clone()))
            .collect::<Vec<_>>(),
        vec![
            (CHUNK as u64 - 16, "carry".to_owned()),
            (CHUNK as u64 - 4, "straddle".to_owned()),
            (CHUNK as u64 + 64, "interior".to_owned()),
        ]
    );
    // Overlap bytes are delivered twice but counted once.
    assert_eq!(report.scope.scanned_bytes, (CHUNK * 3) as u64);
}

/// Live inspection is available on every supported host, so this contract is proven
/// natively rather than by cross-compilation.
#[cfg(any(target_os = "macos", target_os = "linux", windows))]
#[test]
fn live_source_describes_a_running_process_without_proving_any_byte() {
    let target = SyntheticTarget::start();

    let inspect = membridge_json(&["inspect", "--pid", &target.pid.to_string()]);
    let data = &inspect["data"];
    assert_eq!(inspect["command"], "inspect");
    assert_eq!(data["source"]["kind"], "live");
    // A running process is not a frozen artifact, and the contract says so.
    assert_eq!(data["source"]["immutable"], false);
    assert_eq!(data["source"]["platform"], std::env::consts::OS);
    assert_eq!(data["source"]["fingerprint"].as_str().unwrap().len(), 64);
    assert_eq!(data["process"]["id"], format!("pid:{}", target.pid));

    let readable = region_at(data, target.readable);
    assert_eq!(readable["readable"], true);
    assert_eq!(readable["state"], "committed");
    assert_eq!(readable["protection"], "read | write");
    // Nothing is captured ahead of time by a live source.
    assert_eq!(readable["captured_bytes"], Value::Null);

    let inaccessible = region_at(data, target.noaccess);
    assert_eq!(inaccessible["readable"], false);
    assert_eq!(inaccessible["protection"], "none");

    let coverage = &data["coverage"];
    assert_eq!(coverage["metadata_complete"], true);
    assert_eq!(coverage["captured_readable_bytes"], 0);
    assert_eq!(coverage["coverage_complete"], false);
    assert_eq!(
        coverage["limitations"],
        json!(["READS_NOT_ATTEMPTED", "EXPECTED_READABLE_SCOPE_UNPROVEN"])
    );
    let observation = &coverage["observation"];
    assert!(
        observation["completed_at_unix_ms"].as_u64().unwrap()
            >= observation["started_at_unix_ms"].as_u64().unwrap()
    );

    assert!(
        data["modules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|module| module["name"]
                .as_str()
                .unwrap()
                .to_ascii_lowercase()
                .contains("synthetic-target")),
        "the target's own image is missing from the module list"
    );
}

#[cfg(any(target_os = "macos", target_os = "linux", windows))]
#[test]
fn live_scan_finds_planted_canaries_and_never_enters_inaccessible_memory() {
    let target = SyntheticTarget::start();
    let block = 64 * 1024_u64;

    let readable_scope = json!({
        "ranges": [{"start": format!("0x{:x}", target.readable), "length": format!("0x{block:x}")}]
    });
    let report = live_scan(&target, canary_patterns(), Some(readable_scope));
    assert_eq!(report["scan_complete"], true);
    assert_eq!(report["scope"]["selected_bytes"].as_u64().unwrap(), block);
    assert_eq!(report["scope"]["scanned_bytes"].as_u64().unwrap(), block);

    let found: Vec<(u64, String)> = report["matches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|found| {
            (
                u64::from_str_radix(
                    found["address"].as_str().unwrap().trim_start_matches("0x"),
                    16,
                )
                .unwrap(),
                found["tags"][0].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert_eq!(
        found,
        vec![
            (target.readable, "readable".to_owned()),
            (target.noaccess - 20, "edge".to_owned()),
        ],
        "both canaries must be found at their exact planted addresses"
    );

    // Selecting the inaccessible block resolves - the region exists - but not one byte
    // of it is scanned, and the absence of a match there is never claimed as proof.
    let inaccessible_scope = json!({
        "ranges": [{"start": format!("0x{:x}", target.noaccess), "length": format!("0x{block:x}")}]
    });
    let refused = live_scan(&target, canary_patterns(), Some(inaccessible_scope));
    assert_eq!(refused["scope"]["selected_bytes"].as_u64().unwrap(), block);
    assert_eq!(refused["scope"]["scanned_bytes"].as_u64().unwrap(), 0);
    assert_eq!(refused["matches"], json!([]));
    assert!(
        refused["coverage"]["unavailable_readable_bytes"]
            .as_u64()
            .unwrap()
            > 0
    );
}

#[cfg(any(target_os = "macos", target_os = "linux", windows))]
#[test]
fn live_read_stops_at_the_first_inaccessible_page() {
    let target = SyntheticTarget::start();

    let straddling = membridge_json(&[
        "read",
        "--pid",
        &target.pid.to_string(),
        "--address",
        &format!("0x{:x}", target.noaccess - 32),
        "--length",
        "64",
    ]);
    let data = &straddling["data"];
    assert_eq!(data["requested_bytes"], 64);
    assert_eq!(data["returned_bytes"], 32);
    assert_eq!(data["complete"], false);
    assert_eq!(data["segments"].as_array().unwrap().len(), 1);

    let refused = membridge_json(&[
        "read",
        "--pid",
        &target.pid.to_string(),
        "--address",
        &format!("0x{:x}", target.noaccess),
        "--length",
        "64",
    ]);
    assert_eq!(refused["data"]["returned_bytes"], 0);
    assert_eq!(refused["data"]["complete"], false);
    assert_eq!(refused["data"]["segments"], json!([]));
}

#[test]
fn live_target_selection_requires_exactly_one_source() {
    let temp = tempdir().unwrap();
    let dump_path = temp.path().join("fixture.dmp");
    write_fixture(&dump_path);

    for arguments in [
        vec!["inspect".to_owned()],
        vec![
            "inspect".to_owned(),
            dump_path.to_string_lossy().into_owned(),
            "--pid".to_owned(),
            "1".to_owned(),
        ],
    ] {
        let failure = Command::cargo_bin("membridge")
            .unwrap()
            .args(&arguments)
            .assert()
            .failure()
            .get_output()
            .stdout
            .clone();
        let failure: Value = serde_json::from_slice(&failure).unwrap();
        assert_eq!(failure["error"]["code"], "INVALID_ARGUMENT");
    }
}

#[test]
fn live_source_rejects_an_unknown_process() {
    // PID 0 is never an inspectable user process on any supported host.
    let failure = Command::cargo_bin("membridge")
        .unwrap()
        .args(["inspect", "--pid", "0"])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let failure: Value = serde_json::from_slice(&failure).unwrap();
    assert!(
        ["PROCESS_NOT_FOUND", "PROCESS_ACCESS_DENIED"]
            .contains(&failure["error"]["code"].as_str().unwrap()),
        "unexpected error: {failure}"
    );
}

#[cfg(any(target_os = "macos", target_os = "linux", windows))]
fn canary_patterns() -> Value {
    json!([
        {"tag": "readable", "value": {"kind": "utf8", "text": "MBRIDGE-CAPTURE-READABLE!!"}},
        {"tag": "edge", "value": {"kind": "utf8", "text": "MBRIDGE-EDGE-CANARY!"}}
    ])
}

#[cfg(any(target_os = "macos", target_os = "linux", windows))]
fn live_scan(target: &SyntheticTarget, patterns: Value, scope: Option<Value>) -> Value {
    let temp = tempdir().unwrap();
    let spec_path = temp.path().join("scan.json");
    let mut value = json!({"schema": 2, "patterns": patterns, "max_matches": 100});
    if let Some(scope) = scope {
        value["scope"] = scope;
    }
    fs::write(&spec_path, value.to_string()).unwrap();

    let output = membridge_json(&[
        "scan",
        "--pid",
        &target.pid.to_string(),
        "--spec",
        &spec_path.to_string_lossy(),
    ]);
    output["data"]["report"].clone()
}

#[cfg(any(target_os = "macos", target_os = "linux", windows))]
fn region_at(data: &Value, address: u64) -> Value {
    data["regions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|region| {
            let base = u64::from_str_radix(
                region["base"].as_str().unwrap().trim_start_matches("0x"),
                16,
            )
            .unwrap();
            let size = region["size"].as_u64().unwrap();
            (base..base + size).contains(&address)
        })
        .unwrap_or_else(|| panic!("no region covers 0x{address:x}"))
        .clone()
}

fn membridge_json(arguments: &[&str]) -> Value {
    let output = Command::cargo_bin("membridge")
        .unwrap()
        .args(arguments)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice(&output).expect("one compact JSON object on stdout")
}

fn spec(value: Value) -> ScanSpec {
    serde_json::from_value(value).expect("scan specification deserializes")
}

fn canary_text() -> &'static str {
    std::str::from_utf8(CANARY).expect("the fixture canary is ASCII")
}

/// Two differently tagged patterns describing the same canary bytes, so tag
/// aggregation and scope behavior are exercised together.
fn canary_spec(max_matches: usize, scope: Option<Value>) -> ScanSpec {
    let mut value = json!({
        "schema": 2,
        "patterns": [
            {"tag": "canary-a", "value": {"kind": "utf8", "text": canary_text()}},
            {"tag": "canary-b", "value": {"kind": "utf8", "text": canary_text()}}
        ],
        "max_matches": max_matches
    });
    if let Some(scope) = scope {
        value["scope"] = scope;
    }
    spec(value)
}

fn fixture_process(path: &std::path::Path) -> std::sync::Arc<dyn ProcessMemory> {
    write_fixture(path);
    MinidumpSource::open(path)
        .unwrap()
        .open_process("process:0")
        .unwrap()
}

fn addresses(report: &ScanReport) -> Vec<u64> {
    report.matches.iter().map(|found| found.address.0).collect()
}
