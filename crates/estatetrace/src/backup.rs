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

#[cfg(test)]
mod tests {
    use super::*;
    use estatetrace_core::SettingsDoc;
    use serde_json::json;
    use std::fs;
    use std::io::Read;

    fn write_profile(profile: &Path) {
        fs::create_dir_all(profile.join("packs")).unwrap();
        fs::create_dir_all(profile.join("themes")).unwrap();
        fs::write(profile.join("estatetrace.db"), b"sqlite-placeholder").unwrap();

        let settings = SettingsDoc {
            scan_interval_minutes: 30,
            operations_timezone: Some("America/Chicago".into()),
            chat_history_enabled: false,
            retention: json!({}),
            production_mappings: json!({}),
            servicenow: Some(json!({
                "instance_url": "https://example.service-now.com",
                "username": "svc.estatetrace"
            })),
            chat: Some(json!({
                "gateway_url": "https://apim.example/openai",
                "deployment": "gpt",
                "header_name": "Ocp-Apim-Subscription-Key"
            })),
            theme_path: Some("themes/company.yaml".into()),
        };
        let text = serde_json::to_string_pretty(&settings).unwrap();
        assert!(!text.to_ascii_lowercase().contains("password"));
        fs::write(profile.join("settings.json"), text).unwrap();
        fs::write(
            profile.join("themes/company.yaml"),
            "name: Company\naccent: \"#0b6e4f\"\n",
        )
        .unwrap();
        fs::write(profile.join("packs/pilot.json"), "{}").unwrap();
    }

    #[test]
    fn ac06_backup_restore_roundtrip_preserves_settings_and_theme() {
        let src = tempfile::tempdir().unwrap();
        let dest_profile = tempfile::tempdir().unwrap();
        write_profile(src.path());

        let archive = src.path().join("backups/test.zip");
        fs::create_dir_all(archive.parent().unwrap()).unwrap();
        create_backup(src.path(), &archive).unwrap();

        let file = fs::File::open(&archive).unwrap();
        let mut zip = ZipArchive::new(file).unwrap();
        let mut names = Vec::new();
        for i in 0..zip.len() {
            let mut f = zip.by_index(i).unwrap();
            names.push(f.name().to_string());
            let mut buf = String::new();
            let _ = f.read_to_string(&mut buf);
            let lower = buf.to_ascii_lowercase();
            assert!(
                !lower.contains("password") && !lower.contains("\"key\":"),
                "backup blob leaked secret-like field in {}",
                f.name()
            );
        }
        assert!(names.iter().any(|n| n == "settings.json"));
        assert!(names.iter().any(|n| n.starts_with("themes/")));
        assert!(names.iter().any(|n| n.starts_with("packs/")));

        restore_backup(&archive, dest_profile.path()).unwrap();
        let restored = fs::read_to_string(dest_profile.path().join("settings.json")).unwrap();
        let doc: SettingsDoc = serde_json::from_str(&restored).unwrap();
        assert_eq!(doc.scan_interval_minutes, 30);
        assert_eq!(
            doc.operations_timezone.as_deref(),
            Some("America/Chicago")
        );
        assert!(dest_profile.path().join("themes/company.yaml").exists());
        assert!(dest_profile.path().join("packs/pilot.json").exists());
    }
}
