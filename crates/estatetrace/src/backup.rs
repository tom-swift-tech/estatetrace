use anyhow::{Context, Result};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zip::write::SimpleFileOptions;
use zip::{ZipArchive, ZipWriter};

pub fn create_backup(profile: &Path, dest: &Path) -> Result<()> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = File::create(dest).with_context(|| format!("create {}", dest.display()))?;
    let mut zip = ZipWriter::new(file);
    let opts = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    for rel in [
        "estatetrace.db",
        "estatetrace.db-wal",
        "estatetrace.db-shm",
        "settings.json",
    ] {
        let path = profile.join(rel);
        if path.exists() {
            add_file(&mut zip, &path, rel, opts)?;
        }
    }

    add_dir(&mut zip, &profile.join("packs"), "packs", opts)?;
    add_dir(&mut zip, &profile.join("themes"), "themes", opts)?;

    zip.finish()?;
    Ok(())
}

fn add_file(
    zip: &mut ZipWriter<File>,
    path: &Path,
    name: &str,
    opts: SimpleFileOptions,
) -> Result<()> {
    zip.start_file(name, opts)?;
    let mut f = File::open(path)?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    zip.write_all(&buf)?;
    Ok(())
}

fn add_dir(
    zip: &mut ZipWriter<File>,
    dir: &Path,
    prefix: &str,
    opts: SimpleFileOptions,
) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in walkdir(dir)? {
        let rel = entry.strip_prefix(dir)?;
        let name = format!("{}/{}", prefix, rel.to_string_lossy().replace('\\', "/"));
        if entry.is_file() {
            add_file(zip, &entry, &name, opts)?;
        }
    }
    Ok(())
}

fn walkdir(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            out.extend(walkdir(&path)?);
        } else {
            out.push(path);
        }
    }
    Ok(out)
}

pub fn restore_backup(archive: &Path, dest_profile: &Path) -> Result<()> {
    std::fs::create_dir_all(dest_profile)?;
    let file = File::open(archive)?;
    let mut zip = ZipArchive::new(file)?;
    for i in 0..zip.len() {
        let mut file = zip.by_index(i)?;
        let name = file
            .enclosed_name()
            .map(|p| p.to_path_buf())
            .ok_or_else(|| anyhow::anyhow!("unsafe path in archive"))?;
        let outpath = dest_profile.join(name);
        if let Some(parent) = outpath.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut outfile = File::create(&outpath)?;
        std::io::copy(&mut file, &mut outfile)?;
    }
    Ok(())
}