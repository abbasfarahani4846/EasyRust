use std::{
    env, fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

fn files_in(directory: &Path) -> io::Result<Vec<PathBuf>> {
    if !directory.is_dir() {
        return Ok(Vec::new());
    }
    let mut files = fs::read_dir(directory)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<io::Result<Vec<_>>>()?;
    files.sort();
    Ok(files)
}

fn main() -> io::Result<()> {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "CARGO_MANIFEST_DIR is missing")
    })?);
    let output = PathBuf::from(env::var_os("OUT_DIR").ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "OUT_DIR is missing")
    })?);

    println!("cargo:rerun-if-changed=assets/flags");
    println!("cargo:rerun-if-changed=assets/fonts");

    let mut flags = fs::File::create(output.join("flags.rs"))?;
    writeln!(
        flags,
        "pub fn flag_png(code: &str) -> Option<&'static [u8]> {{ match code {{"
    )?;
    for path in files_in(&root.join("assets/flags"))? {
        if path.extension().and_then(|s| s.to_str()) != Some("png") {
            continue;
        }
        let Some(code) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if code.len() != 2 || !code.bytes().all(|b| b.is_ascii_lowercase()) {
            continue;
        }
        writeln!(
            flags,
            "{code:?} => Some(include_bytes!({:?}).as_slice()),",
            path
        )?;
    }
    writeln!(flags, "_ => None, }} }}")?;

    let mut fonts = fs::File::create(output.join("fonts.rs"))?;
    writeln!(
        fonts,
        "pub fn font_bytes(name: &str) -> Option<&'static [u8]> {{ match name {{"
    )?;
    for name in ["Vazirmatn-400", "Vazirmatn-700"] {
        let path = root.join("assets/fonts").join(format!("{name}.ttf"));
        if path.is_file() {
            writeln!(
                fonts,
                "{name:?} => Some(include_bytes!({:?}).as_slice()),",
                path
            )?;
        }
    }
    writeln!(fonts, "_ => None, }} }}")?;
    Ok(())
}
