mod common;

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::path::Path;

use assert_cmd::Command;
use membridge::scan::{ExactPatternSpec, ScanSpec, scan};
use membridge::source::{
    CoverageLimitation, MAX_COVERAGE_LIMITATIONS, MemorySource, MinidumpSource,
};
use serde_json::Value;
use tempfile::tempdir;

use common::{
    BASE, BOUNDARY_MATCH, CANARY, FIRST_MATCH, MemoryMetadataFixture, NOACCESS_DECOY,
    write_coverage_fixture, write_fixture,
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

    assert_eq!(MAX_COVERAGE_LIMITATIONS, 4);
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
        2
    );
    assert_eq!(
        scan["data"]["report"]["matches"][0]["address"],
        "0x0000000140000100"
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
    assert_eq!(
        installed["data"]["binary_version"],
        env!("CARGO_PKG_VERSION")
    );
    assert_eq!(
        installed["data"]["skill_version"],
        env!("CARGO_PKG_VERSION")
    );

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

#[test]
fn cli_requires_exactly_one_skill_destination() {
    let missing = Command::cargo_bin("membridge")
        .unwrap()
        .args(["skill", "install"])
        .assert()
        .failure()
        .code(2)
        .get_output()
        .stdout
        .clone();
    let missing: Value = serde_json::from_slice(&missing).unwrap();
    assert_eq!(missing["command"], "cli");
    assert_eq!(missing["error"]["code"], "INVALID_ARGUMENT");

    let temp = tempdir().unwrap();
    let conflicting = Command::cargo_bin("membridge")
        .unwrap()
        .args(["skill", "install", "--target"])
        .arg(temp.path())
        .arg("--omp")
        .assert()
        .failure()
        .code(2)
        .get_output()
        .stdout
        .clone();
    let conflicting: Value = serde_json::from_slice(&conflicting).unwrap();
    assert_eq!(conflicting["command"], "cli");
    assert_eq!(conflicting["error"]["code"], "INVALID_ARGUMENT");
}

#[cfg(unix)]
#[test]
fn cli_installs_the_skill_into_the_active_omp_profile() {
    let temp = tempdir().unwrap();
    let bin_dir = temp.path().join("bin");
    let agent_root = temp.path().join("active-omp-agent");
    write_fake_omp(&bin_dir);

    let installed = Command::cargo_bin("membridge")
        .unwrap()
        .args(["skill", "install", "--omp"])
        .env("PATH", &bin_dir)
        .env(
            "MEMBRIDGE_TEST_OMP_OUTPUT",
            format!("{}\n", agent_root.display()),
        )
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let installed: Value = serde_json::from_slice(&installed).unwrap();
    let destination = agent_root.join("skills").join("membridge");

    assert_eq!(
        installed["data"]["destination"],
        destination.to_string_lossy().as_ref()
    );
    assert_eq!(
        fs::read_to_string(destination.join("SKILL.md")).unwrap(),
        include_str!("../.agents/skills/membridge/SKILL.md")
    );
    assert_eq!(
        fs::read_to_string(destination.join("examples").join("canary-batch.json")).unwrap(),
        include_str!("../.agents/skills/membridge/examples/canary-batch.json")
    );
}

#[cfg(unix)]
#[test]
fn cli_rejects_unavailable_or_invalid_omp_discovery() {
    let temp = tempdir().unwrap();
    let empty_path = temp.path().join("empty-path");
    fs::create_dir(&empty_path).unwrap();

    let missing = Command::cargo_bin("membridge")
        .unwrap()
        .args(["skill", "install", "--omp"])
        .env("PATH", &empty_path)
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let missing: Value = serde_json::from_slice(&missing).unwrap();
    assert_eq!(missing["command"], "skill.install");
    assert_eq!(missing["error"]["code"], "OMP_NOT_FOUND");

    let bin_dir = temp.path().join("bin");
    write_fake_omp(&bin_dir);
    let invalid_outputs = [
        ("", "empty path"),
        ("first\nsecond\n", "multiple lines"),
        ("relative/path\n", "non-absolute path"),
        (&"x".repeat(4097), "exceeds 4096 bytes"),
    ];
    for (output, expected_message) in invalid_outputs {
        let failure = Command::cargo_bin("membridge")
            .unwrap()
            .args(["skill", "install", "--omp"])
            .env("PATH", &bin_dir)
            .env("MEMBRIDGE_TEST_OMP_OUTPUT", output)
            .assert()
            .failure()
            .get_output()
            .stdout
            .clone();
        let failure: Value = serde_json::from_slice(&failure).unwrap();
        assert_eq!(failure["error"]["code"], "OMP_DISCOVERY_FAILED");
        assert!(
            failure["error"]["message"]
                .as_str()
                .unwrap()
                .contains(expected_message)
        );
    }

    let failed = Command::cargo_bin("membridge")
        .unwrap()
        .args(["skill", "install", "--omp"])
        .env("PATH", &bin_dir)
        .env("MEMBRIDGE_TEST_OMP_OUTPUT", "/ignored\n")
        .env("MEMBRIDGE_TEST_OMP_STATUS", "9")
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let failed: Value = serde_json::from_slice(&failed).unwrap();
    assert_eq!(failed["error"]["code"], "OMP_DISCOVERY_FAILED");
    assert!(
        failed["error"]["message"]
            .as_str()
            .unwrap()
            .contains("exited with")
    );
}

#[cfg(unix)]
fn write_fake_omp(bin_dir: &Path) {
    fs::create_dir_all(bin_dir).unwrap();
    let executable = bin_dir.join("omp");
    fs::write(
        &executable,
        "#!/bin/sh\n\
         if [ \"$1\" != config ] || [ \"$2\" != path ]; then exit 64; fi\n\
         printf '%s' \"$MEMBRIDGE_TEST_OMP_OUTPUT\"\n\
         exit \"${MEMBRIDGE_TEST_OMP_STATUS:-0}\"\n",
    )
    .unwrap();
    let mut permissions = fs::metadata(&executable).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(executable, permissions).unwrap();
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
