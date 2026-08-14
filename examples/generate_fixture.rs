use std::env;
use std::fs;
use std::path::PathBuf;

#[allow(dead_code)]
#[path = "../tests/common/mod.rs"]
mod fixture;

fn main() {
    let path = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .expect("usage: generate_fixture <output.dmp>");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create fixture output directory");
    }
    fixture::write_fixture(&path);
    println!("{}", path.display());
}
