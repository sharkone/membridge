mod common;

use std::fs;

use assert_cmd::Command;
use membridge::scan::{ExactPatternSpec, ScanSpec, scan};
use membridge::source::{MemorySource, MinidumpSource};
use serde_json::Value;
use tempfile::tempdir;

use common::{BASE, BOUNDARY_MATCH, CANARY, FIRST_MATCH, NOACCESS_DECOY, write_fixture};

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

    let coverage = process.coverage();
    assert_eq!(coverage.expected_readable_bytes, 0x3000);
    assert_eq!(coverage.captured_readable_bytes, 0x2000);
    assert_eq!(coverage.unavailable_readable_bytes, 0x1000);
    assert!(coverage.metadata_complete);
    assert!(!coverage.coverage_complete);
}

#[test]
fn exact_scan_finds_boundary_matches_and_skips_noaccess_memory() {
    let temp = tempdir().unwrap();
    let dump_path = temp.path().join("fixture.dmp");
    write_fixture(&dump_path);
    let source = MinidumpSource::open(&dump_path).unwrap();
    let process = source.open_process("process:0").unwrap();

    let report = scan(process.as_ref(), &spec(100, two_identical_patterns())).unwrap();
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
    assert_eq!(report.matches[0].module.as_ref().unwrap().rva, 0x100);
}

#[test]
fn match_quota_is_explicit_and_deterministic() {
    let temp = tempdir().unwrap();
    let dump_path = temp.path().join("fixture.dmp");
    write_fixture(&dump_path);
    let source = MinidumpSource::open(&dump_path).unwrap();
    let process = source.open_process("process:0").unwrap();

    let report = scan(process.as_ref(), &spec(1, two_identical_patterns())).unwrap();
    assert!(!report.scan_complete);
    assert_eq!(report.terminal_reason, "match_limit");
    assert_eq!(report.matches.len(), 1);
    assert_eq!(report.matches[0].address.0, FIRST_MATCH);
    assert_eq!(report.next_address.unwrap().0, BOUNDARY_MATCH);
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
        serde_json::to_vec(&serde_json::json!({
            "schema": 1,
            "patterns": [{
                "tag": "canary",
                "bytes_hex": hex::encode(CANARY),
                "alignment": 1
            }],
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
    assert_eq!(inspect["schema"], 1);
    assert_eq!(inspect["ok"], true);
    assert_eq!(inspect["command"], "inspect");
    assert_eq!(inspect["data"]["coverage"]["coverage_complete"], false);

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
        2
    );
    assert_eq!(
        scan["data"]["report"]["matches"][0]["address"],
        "0x0000000140000100"
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
fn cli_installs_the_version_matched_agent_skill() {
    let temp = tempdir().unwrap();
    let skills_root = temp.path().join("skills");

    let installed = Command::cargo_bin("membridge")
        .unwrap()
        .args(["skill", "install", "--target"])
        .arg(&skills_root)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let installed: Value = serde_json::from_slice(&installed).unwrap();
    assert_eq!(installed["command"], "skill.install");
    assert_eq!(installed["data"]["replaced"], false);

    let installed_skill =
        fs::read_to_string(skills_root.join("membridge").join("SKILL.md")).unwrap();
    assert_eq!(
        installed_skill,
        include_str!("../.agents/skills/membridge/SKILL.md")
    );
    let installed_example = fs::read_to_string(
        skills_root
            .join("membridge")
            .join("examples")
            .join("canary-batch.json"),
    )
    .unwrap();
    assert_eq!(
        installed_example,
        include_str!("../.agents/skills/membridge/examples/canary-batch.json")
    );

    let replaced = Command::cargo_bin("membridge")
        .unwrap()
        .args(["skill", "install", "--target"])
        .arg(&skills_root)
        .arg("--force")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let replaced: Value = serde_json::from_slice(&replaced).unwrap();
    assert_eq!(replaced["data"]["replaced"], true);
}

fn spec(max_matches: usize, patterns: Vec<ExactPatternSpec>) -> ScanSpec {
    ScanSpec {
        schema: 1,
        patterns,
        max_matches,
    }
}

fn two_identical_patterns() -> Vec<ExactPatternSpec> {
    vec![
        ExactPatternSpec {
            tag: "canary-a".into(),
            bytes_hex: hex::encode(CANARY),
            alignment: 1,
        },
        ExactPatternSpec {
            tag: "canary-b".into(),
            bytes_hex: hex::encode(CANARY),
            alignment: 1,
        },
    ]
}
