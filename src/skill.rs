use serde::Serialize;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use crate::{Error, Result};

const SKILL: &str = include_str!("../.agents/skills/membridge/SKILL.md");
const CANARY_BATCH: &str = include_str!("../.agents/skills/membridge/examples/canary-batch.json");
const INSTALL_SH: &str = include_str!("../.agents/skills/membridge/scripts/install.sh");
const INSTALL_PS1: &str = include_str!("../.agents/skills/membridge/scripts/install.ps1");

#[derive(Debug, Clone, Serialize)]
pub struct InstallReport {
    pub destination: String,
    pub files: Vec<&'static str>,
    pub replaced: bool,
    pub binary_version: &'static str,
    pub skill_version: &'static str,
}

pub fn install(force: bool) -> Result<InstallReport> {
    let skills_root = user_home()?.join(".agents").join("skills");
    install_at(&skills_root, force)
}

fn install_at(target_root: &Path, force: bool) -> Result<InstallReport> {
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
    let backup = target_root.join(format!(".membridge-backup-{}", std::process::id()));
    if backup.exists() {
        return Err(Error::InvalidArgument(format!(
            "skill backup {} already exists; preserve or remove it before retrying",
            backup.display()
        )));
    }
    create_dir_all(&staging.join("examples"))?;
    create_dir_all(&staging.join("scripts"))?;
    write(&staging.join("SKILL.md"), SKILL)?;
    write(
        &staging.join("examples").join("canary-batch.json"),
        CANARY_BATCH,
    )?;
    let install_sh = staging.join("scripts").join("install.sh");
    write(&install_sh, INSTALL_SH)?;
    make_executable(&install_sh)?;
    write(&staging.join("scripts").join("install.ps1"), INSTALL_PS1)?;

    if replaced {
        fs::rename(&destination, &backup).map_err(|source| Error::Io {
            path: backup.clone(),
            source,
        })?;
    }
    if let Err(install_error) = fs::rename(&staging, &destination) {
        if replaced {
            if let Err(rollback_error) = fs::rename(&backup, &destination) {
                return Err(Error::Io {
                    path: destination.clone(),
                    source: std::io::Error::other(format!(
                        "install failed: {install_error}; rollback failed: {rollback_error}; previous skill remains at {}",
                        backup.display()
                    )),
                });
            }
        }
        return Err(Error::Io {
            path: destination.clone(),
            source: install_error,
        });
    }
    if replaced {
        remove_dir_all(&backup)?;
    }

    Ok(InstallReport {
        destination: destination.to_string_lossy().into_owned(),
        files: vec![
            "SKILL.md",
            "examples/canary-batch.json",
            "scripts/install.sh",
            "scripts/install.ps1",
        ],
        replaced,
        binary_version: env!("CARGO_PKG_VERSION"),
        skill_version: env!("CARGO_PKG_VERSION"),
    })
}

fn user_home() -> Result<PathBuf> {
    #[cfg(windows)]
    let home = env::var_os("USERPROFILE").or_else(|| env::var_os("HOME"));
    #[cfg(not(windows))]
    let home = env::var_os("HOME");

    let home = home.filter(|value| !value.is_empty()).ok_or_else(|| {
        Error::HomeDirectoryUnavailable("the user home environment variable is unset".into())
    })?;
    let home = PathBuf::from(home);
    if !home.is_absolute() {
        return Err(Error::HomeDirectoryUnavailable(format!(
            "the user home path is not absolute: {}",
            home.display()
        )));
    }
    Ok(home)
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

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)
        .map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })?
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<()> {
    Ok(())
}

fn write(path: &Path, contents: &str) -> Result<()> {
    fs::write(path, contents).map_err(|source| Error::Io {
        path: PathBuf::from(path),
        source,
    })
}
