use serde::Serialize;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::{Error, Result};

const SKILL: &str = include_str!("../.agents/skills/membridge/SKILL.md");
const CANARY_BATCH: &str = include_str!("../.agents/skills/membridge/examples/canary-batch.json");
const MAX_OMP_PATH_OUTPUT: u64 = 4096;

#[derive(Debug, Clone, Serialize)]
pub struct InstallReport {
    pub destination: String,
    pub files: Vec<&'static str>,
    pub replaced: bool,
    pub binary_version: &'static str,
    pub skill_version: &'static str,
}

pub fn install_for_omp(force: bool) -> Result<InstallReport> {
    let agent_root = omp_agent_root()?;
    install(&agent_root.join("skills"), force)
}

pub fn install(target_root: &Path, force: bool) -> Result<InstallReport> {
    create_dir_all(target_root)?;
    let destination = target_root.join("membridge");
    let replaced = destination.exists();
    if replaced && !force {
        return Err(Error::InvalidArgument(format!(
            "skill destination {} already exists; pass --force to replace it",
            destination.display()
        )));
    }

    let staging = target_root.join(format!(".membridge-install-{}", std::process::id()));
    if staging.exists() {
        remove_dir_all(&staging)?;
    }
    create_dir_all(&staging.join("examples"))?;
    write(&staging.join("SKILL.md"), SKILL)?;
    write(
        &staging.join("examples").join("canary-batch.json"),
        CANARY_BATCH,
    )?;

    if replaced {
        remove_dir_all(&destination)?;
    }
    fs::rename(&staging, &destination).map_err(|source| Error::Io {
        path: destination.clone(),
        source,
    })?;

    Ok(InstallReport {
        destination: destination.to_string_lossy().into_owned(),
        files: vec!["SKILL.md", "examples/canary-batch.json"],
        replaced,
        binary_version: env!("CARGO_PKG_VERSION"),
        skill_version: env!("CARGO_PKG_VERSION"),
    })
}

fn omp_agent_root() -> Result<PathBuf> {
    let mut child = Command::new("omp")
        .args(["config", "path"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|source| {
            if source.kind() == std::io::ErrorKind::NotFound {
                Error::OmpNotFound
            } else {
                Error::OmpDiscovery(format!("could not start `omp config path`: {source}"))
            }
        })?;

    let mut output = Vec::with_capacity(MAX_OMP_PATH_OUTPUT as usize + 1);
    let read_result = child
        .stdout
        .take()
        .expect("piped OMP stdout must be available")
        .take(MAX_OMP_PATH_OUTPUT + 1)
        .read_to_end(&mut output);
    if let Err(source) = read_result {
        let _ = child.kill();
        let _ = child.wait();
        return Err(Error::OmpDiscovery(format!(
            "could not read `omp config path` output: {source}"
        )));
    }
    if output.len() > MAX_OMP_PATH_OUTPUT as usize {
        let _ = child.kill();
        let _ = child.wait();
        return Err(Error::OmpDiscovery(format!(
            "`omp config path` output exceeds {MAX_OMP_PATH_OUTPUT} bytes"
        )));
    }

    let status = child
        .wait()
        .map_err(|source| Error::OmpDiscovery(format!("could not wait for OMP: {source}")))?;
    if !status.success() {
        return Err(Error::OmpDiscovery(format!(
            "`omp config path` exited with {status}"
        )));
    }

    let output = std::str::from_utf8(&output)
        .map_err(|_| Error::OmpDiscovery("`omp config path` returned non-UTF-8 output".into()))?;
    let output = output
        .strip_suffix("\r\n")
        .or_else(|| output.strip_suffix('\n'))
        .unwrap_or(output);
    if output.is_empty() {
        return Err(Error::OmpDiscovery(
            "`omp config path` returned an empty path".into(),
        ));
    }
    if output.contains('\r') || output.contains('\n') {
        return Err(Error::OmpDiscovery(
            "`omp config path` returned multiple lines".into(),
        ));
    }

    let path = PathBuf::from(output);
    if !path.is_absolute() {
        return Err(Error::OmpDiscovery(
            "`omp config path` returned a non-absolute path".into(),
        ));
    }
    Ok(path)
}

fn create_dir_all(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn remove_dir_all(path: &Path) -> Result<()> {
    fs::remove_dir_all(path).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn write(path: &Path, contents: &str) -> Result<()> {
    fs::write(path, contents).map_err(|source| Error::Io {
        path: PathBuf::from(path),
        source,
    })
}
