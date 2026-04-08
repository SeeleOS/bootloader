use crate::file_data_source::FileDataSource;
use anyhow::Context;
use fatfs::Dir;
use std::fs::File;
use std::{collections::BTreeMap, fs, path::Path};

use crate::KERNEL_FILE_NAME;

pub fn create_fat_filesystem(
    files: BTreeMap<&str, &FileDataSource>,
    out_fat_path: &Path,
) -> anyhow::Result<()> {
    const MB: u64 = 1024 * 1024;
    const INITIAL_PADDING: u64 = 4 * MB;
    const MAX_ATTEMPTS: usize = 8;

    // calculate needed size
    let mut needed_size = 0;
    for source in files.values() {
        needed_size += source.len()?;
    }

    let mut fat_size = round_up_to_mib(needed_size.saturating_add(INITIAL_PADDING));

    // choose a file system label
    let mut label = *b"MY_RUST_OS!";

    // This __should__ always be a file, but maybe not. Should we allow the caller to set the volume label instead?
    if let Some(FileDataSource::File(path)) = files.get(KERNEL_FILE_NAME) {
        if let Some(name) = path.file_stem() {
            let converted = name.to_string_lossy();
            let name = converted.as_bytes();
            let mut new_label = [0u8; 11];
            let name = &name[..usize::min(new_label.len(), name.len())];
            let slice = &mut new_label[..name.len()];
            slice.copy_from_slice(name);
            label = new_label;
        }
    }

    for _ in 0..MAX_ATTEMPTS {
        match format_and_copy_files(fat_size, label, &files, out_fat_path) {
            Ok(()) => return Ok(()),
            Err(err) if is_no_space_error(&err) => {
                fat_size = fat_size.saturating_mul(2);
            }
            Err(err) => return Err(err),
        }
    }

    Err(anyhow::anyhow!(
        "failed to create FAT filesystem image after {MAX_ATTEMPTS} attempts"
    ))
}

pub fn add_files_to_image(
    root_dir: &Dir<&File>,
    files: BTreeMap<&str, &FileDataSource>,
) -> anyhow::Result<()> {
    for (target_path_raw, source) in files {
        let target_path = Path::new(target_path_raw);
        // create parent directories
        let ancestors: Vec<_> = target_path.ancestors().skip(1).collect();
        for ancestor in ancestors.into_iter().rev().skip(1) {
            root_dir
                .create_dir(&ancestor.display().to_string())
                .with_context(|| {
                    format!(
                        "failed to create directory `{}` on FAT filesystem",
                        ancestor.display()
                    )
                })?;
        }

        let mut new_file = root_dir
            .create_file(target_path_raw)
            .with_context(|| format!("failed to create file at `{}`", target_path.display()))?;
        new_file.truncate().unwrap();

        source.copy_to(&mut new_file).with_context(|| {
            format!(
                "failed to copy source data `{:?}` to file at `{}`",
                source,
                target_path.display()
            )
        })?;
    }

    Ok(())
}

fn format_and_copy_files(
    fat_size: u64,
    label: [u8; 11],
    files: &BTreeMap<&str, &FileDataSource>,
    out_fat_path: &Path,
) -> anyhow::Result<()> {
    let fat_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(out_fat_path)
        .with_context(|| format!("failed to create FAT image at `{}`", out_fat_path.display()))?;
    fat_file
        .set_len(fat_size)
        .with_context(|| format!("failed to resize FAT image at `{}`", out_fat_path.display()))?;

    let format_options = fatfs::FormatVolumeOptions::new().volume_label(label);
    fatfs::format_volume(&fat_file, format_options).context("Failed to format FAT file")?;
    let filesystem = fatfs::FileSystem::new(&fat_file, fatfs::FsOptions::new())
        .context("Failed to open FAT file system of UEFI FAT file")?;
    let root_dir = filesystem.root_dir();

    add_files_to_image(&root_dir, files.clone())
}

fn round_up_to_mib(bytes: u64) -> u64 {
    const MB: u64 = 1024 * 1024;
    bytes.saturating_add(MB - 1) / MB * MB
}

fn is_no_space_error(err: &anyhow::Error) -> bool {
    err.chain()
        .any(|cause| cause.to_string().contains("No space left on device"))
}

#[cfg(test)]
mod tests {
    use super::create_fat_filesystem;
    use crate::file_data_source::FileDataSource;
    use std::collections::BTreeMap;
    use std::fs;
    use tempfile::NamedTempFile;

    #[test]
    fn creates_filesystem_for_large_ramdisk() {
        let ramdisk = NamedTempFile::new().unwrap();
        ramdisk.as_file().set_len(512 * 1024 * 1024).unwrap();

        let out_fat = NamedTempFile::new().unwrap();
        let ramdisk_source = FileDataSource::File(ramdisk.path().to_path_buf());
        let mut files = BTreeMap::new();
        files.insert("ramdisk", &ramdisk_source);

        create_fat_filesystem(files, out_fat.path()).unwrap();

        let fat_file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(out_fat.path())
            .unwrap();
        let fs = fatfs::FileSystem::new(&fat_file, fatfs::FsOptions::new()).unwrap();
        let stats = fs.stats().unwrap();
        assert!(stats.free_clusters() > 0);
    }
}
