use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::{Error, Result};

const SKILL: &str = include_str!("../.agents/skills/membridge/SKILL.md");
const CANARY_BATCH: &str = include_str!("../.agents/skills/membridge/examples/canary-batch.json");

#[derive(Debug, Clone, Serialize)]
pub struct InstallReport {
    pub destination: String,
    pub files: Vec<&'static str>,
    pub replaced: bool,
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
    })
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
