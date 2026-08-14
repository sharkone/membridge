mod common;

use std::fs;

use assert_cmd::Command;
use membridge::scan::{ExactPatternSpec, ScanSpec, scan};
use membridge::source::{
    CoverageLimitation, MAX_COVERAGE_LIMITATIONS, MemorySource, MinidumpSource,
};
use serde_json::Value;
use tempfile::tempdir;
#[cfg(windows)]
const USER_HOME_ENV: &str = "USERPROFILE";
#[cfg(not(windows))]
const USER_HOME_ENV: &str = "HOME";

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
    let version = env!("CARGO_PKG_VERSION");
    assert!(installed_skill.contains(&format!("`membridge {version}`")));
    assert!(installed_shell.contains(&format!("VERSION=\"{version}\"")));
    assert!(installed_shell.contains(&format!("releases/download/v{version}/")));
    assert!(installed_powershell.contains(&format!("$Version = '{version}'")));
    assert!(installed_powershell.contains(&format!("releases/download/v{version}/")));
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
    let fake_membridge = fake_bin.join("membridge");
    fs::write(
        &fake_membridge,
        format!(
            "#!/bin/sh\nprintf 'membridge {}\\n'\n",
            env!("CARGO_PKG_VERSION")
        ),
    )
    .unwrap();
    let mut permissions = fs::metadata(&fake_membridge).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&fake_membridge, permissions).unwrap();

    let bootstrap = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(".agents/skills/membridge/scripts/install.sh");
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
    fs::write(
        fake_bin.join("membridge.cmd"),
        format!(
            "@echo off\r\necho membridge {}\r\nexit /b 0\r\n",
            env!("CARGO_PKG_VERSION")
        ),
    )
    .unwrap();

    let inherited_path = std::env::var_os("PATH").unwrap();
    let path = std::env::join_paths(
        std::iter::once(fake_bin.as_path()).chain(std::env::split_paths(&inherited_path)),
    )
    .unwrap();
    let powershell = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap())
        .join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let bootstrap = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(".agents/skills/membridge/scripts/install.ps1");
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

    assert!(output.status.success());
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
    let plugin_version = format!("{}.skill.1", env!("CARGO_PKG_VERSION"));
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
