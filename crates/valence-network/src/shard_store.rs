//! On-disk content shard storage.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

/// On-disk storage for erasure-coded shards.
///
/// Directory layout:
/// ```text
/// ~/.valence-node/shards/
///   {content_hash}/
///     {shard_index}       — shard data
///     {shard_index}.tmp   — temp file during atomic write
///   quarantine/
///     {content_hash}/     — quarantined content
///       {shard_index}
/// ```
#[derive(Debug)]
pub struct ShardStore {
    base_dir: PathBuf,
}

impl ShardStore {
    /// Create a new shard store at the given base directory.
    /// Creates the directory structure if it doesn't exist.
    pub fn new(base_dir: PathBuf) -> Result<Self> {
        let shards_dir = base_dir.join("shards");
        let quarantine_dir = base_dir.join("shards").join("quarantine");
        
        fs::create_dir_all(&shards_dir)
            .with_context(|| format!("Failed to create shards dir: {}", shards_dir.display()))?;
        fs::create_dir_all(&quarantine_dir)
            .with_context(|| format!("Failed to create quarantine dir: {}", quarantine_dir.display()))?;
        
        Ok(Self { base_dir })
    }

    /// Default base directory: ~/.valence-node/
    pub fn default_dir() -> PathBuf {
        if let Some(home) = std::env::var_os("HOME") {
            PathBuf::from(home).join(".valence-node")
        } else {
            PathBuf::from(".valence-node")
        }
    }

    /// Store a shard atomically (write to .tmp then rename).
    pub fn store_shard(&self, content_hash: &str, shard_index: u32, data: &[u8]) -> Result<()> {
        let content_dir = self.base_dir.join("shards").join(content_hash);
        fs::create_dir_all(&content_dir)
            .with_context(|| format!("Failed to create content dir: {}", content_dir.display()))?;

        let shard_path = content_dir.join(shard_index.to_string());
        let tmp_path = content_dir.join(format!("{}.tmp", shard_index));

        // Write to temp file with fsync for crash safety
        {
            let mut file = fs::File::create(&tmp_path)
                .context("Failed to create temp shard file")?;
            file.write_all(data)
                .context("Failed to write temp shard file")?;
            file.sync_all()
                .context("Failed to fsync temp shard file")?;
        }

        // Atomic rename
        fs::rename(&tmp_path, &shard_path)
            .context("Failed to rename temp shard file")?;

        debug!(
            content = %content_hash,
            shard = shard_index,
            bytes = data.len(),
            "Stored shard"
        );

        Ok(())
    }

    /// Read a shard from disk.
    pub fn read_shard(&self, content_hash: &str, shard_index: u32) -> Result<Vec<u8>> {
        let shard_path = self.base_dir
            .join("shards")
            .join(content_hash)
            .join(shard_index.to_string());

        let data = fs::read(&shard_path)
            .with_context(|| format!("Failed to read shard from {}", shard_path.display()))?;

        debug!(
            content = %content_hash,
            shard = shard_index,
            bytes = data.len(),
            "Read shard"
        );

        Ok(data)
    }

    /// Check if we have a specific shard.
    pub fn has_shard(&self, content_hash: &str, shard_index: u32) -> bool {
        let shard_path = self.base_dir
            .join("shards")
            .join(content_hash)
            .join(shard_index.to_string());
        shard_path.exists()
    }

    /// Delete all shards for a content hash.
    pub fn delete_content(&self, content_hash: &str) -> Result<()> {
        let content_dir = self.base_dir.join("shards").join(content_hash);
        
        if content_dir.exists() {
            fs::remove_dir_all(&content_dir)
                .with_context(|| format!("Failed to remove content dir: {}", content_dir.display()))?;
            info!(content = %content_hash, "Deleted content");
        }

        Ok(())
    }

    /// Move content to quarantine directory.
    pub fn quarantine_content(&self, content_hash: &str) -> Result<()> {
        let content_dir = self.base_dir.join("shards").join(content_hash);
        let quarantine_dir = self.base_dir.join("shards").join("quarantine").join(content_hash);

        if !content_dir.exists() {
            return Ok(()); // Nothing to quarantine
        }

        if quarantine_dir.exists() {
            // If quarantine dir already exists, remove it first
            fs::remove_dir_all(&quarantine_dir).ok();
        }

        fs::rename(&content_dir, &quarantine_dir)
            .with_context(|| format!(
                "Failed to quarantine {} to {}",
                content_dir.display(),
                quarantine_dir.display()
            ))?;

        warn!(content = %content_hash, "Quarantined content");
        Ok(())
    }

    /// Delete quarantined content.
    pub fn delete_quarantined(&self, content_hash: &str) -> Result<()> {
        let quarantine_dir = self.base_dir.join("shards").join("quarantine").join(content_hash);
        
        if quarantine_dir.exists() {
            fs::remove_dir_all(&quarantine_dir)
                .with_context(|| format!("Failed to remove quarantined dir: {}", quarantine_dir.display()))?;
            info!(content = %content_hash, "Deleted quarantined content");
        }

        Ok(())
    }

    /// Calculate total size of all stored shards.
    pub fn total_size(&self) -> u64 {
        let shards_dir = self.base_dir.join("shards");
        calculate_dir_size(&shards_dir)
    }

    /// Calculate total size of quarantined content.
    pub fn quarantine_size(&self) -> u64 {
        let quarantine_dir = self.base_dir.join("shards").join("quarantine");
        calculate_dir_size(&quarantine_dir)
    }

    /// List all content hashes we have shards for.
    pub fn list_content(&self) -> Vec<String> {
        let shards_dir = self.base_dir.join("shards");
        let mut content_hashes = Vec::new();

        if let Ok(entries) = fs::read_dir(&shards_dir) {
            for entry in entries.flatten() {
                if let Ok(metadata) = entry.metadata()
                    && metadata.is_dir() {
                        let name = entry.file_name();
                        let name_str = name.to_string_lossy();
                        // Skip the quarantine directory
                        if name_str != "quarantine" {
                            content_hashes.push(name_str.to_string());
                        }
                    }
            }
        }

        content_hashes.sort();
        content_hashes
    }

    /// Get shard indices for a specific content hash.
    pub fn list_shards(&self, content_hash: &str) -> Vec<u32> {
        let content_dir = self.base_dir.join("shards").join(content_hash);
        let mut shard_indices = Vec::new();

        if let Ok(entries) = fs::read_dir(&content_dir) {
            for entry in entries.flatten() {
                if let Ok(metadata) = entry.metadata()
                    && metadata.is_file() {
                        let name = entry.file_name();
                        let name_str = name.to_string_lossy();
                        // Skip temp files
                        if !name_str.ends_with(".tmp")
                            && let Ok(index) = name_str.parse::<u32>() {
                                shard_indices.push(index);
                            }
                    }
            }
        }

        shard_indices.sort();
        shard_indices
    }

    /// Get storage statistics.
    pub fn stats(&self) -> StorageStats {
        let total_bytes = self.total_size();
        let quarantine_bytes = self.quarantine_size();
        let content_count = self.list_content().len();

        // Count total shards
        let mut shard_count = 0;
        for content_hash in self.list_content() {
            shard_count += self.list_shards(&content_hash).len();
        }

        StorageStats {
            total_bytes,
            quarantine_bytes,
            content_count,
            shard_count,
        }
    }
}

/// Storage statistics.
#[derive(Debug, Clone)]
pub struct StorageStats {
    pub total_bytes: u64,
    pub quarantine_bytes: u64,
    pub content_count: usize,
    pub shard_count: usize,
}

/// Recursively calculate directory size.
fn calculate_dir_size(path: &Path) -> u64 {
    let mut total = 0u64;

    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            if let Ok(metadata) = entry.metadata() {
                if metadata.is_file() {
                    total += metadata.len();
                } else if metadata.is_dir() {
                    total += calculate_dir_size(&entry.path());
                }
            }
        }
    }

    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn shard_store_create() {
        let tmp = TempDir::new().unwrap();
        let store = ShardStore::new(tmp.path().to_path_buf()).unwrap();
        
        let shards_dir = tmp.path().join("shards");
        assert!(shards_dir.exists());
        
        let quarantine_dir = shards_dir.join("quarantine");
        assert!(quarantine_dir.exists());
    }

    #[test]
    fn shard_store_write_read_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let store = ShardStore::new(tmp.path().to_path_buf()).unwrap();

        let content_hash = "abc123";
        let shard_index = 0;
        let data = b"test shard data";

        store.store_shard(content_hash, shard_index, data).unwrap();
        let read_data = store.read_shard(content_hash, shard_index).unwrap();

        assert_eq!(read_data, data);
    }

    #[test]
    fn shard_store_atomic_write() {
        let tmp = TempDir::new().unwrap();
        let store = ShardStore::new(tmp.path().to_path_buf()).unwrap();

        let content_hash = "def456";
        let shard_index = 1;
        let data = b"atomic test";

        store.store_shard(content_hash, shard_index, data).unwrap();

        // Verify no .tmp files remain
        let content_dir = tmp.path().join("shards").join(content_hash);
        let entries: Vec<_> = fs::read_dir(&content_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();

        assert_eq!(entries.len(), 1);
        assert!(entries[0].file_name().to_string_lossy() == "1");
    }

    #[test]
    fn shard_store_has_shard() {
        let tmp = TempDir::new().unwrap();
        let store = ShardStore::new(tmp.path().to_path_buf()).unwrap();

        let content_hash = "ghi789";
        let shard_index = 2;

        assert!(!store.has_shard(content_hash, shard_index));

        store.store_shard(content_hash, shard_index, b"data").unwrap();

        assert!(store.has_shard(content_hash, shard_index));
    }

    #[test]
    fn shard_store_delete_content() {
        let tmp = TempDir::new().unwrap();
        let store = ShardStore::new(tmp.path().to_path_buf()).unwrap();

        let content_hash = "jkl012";
        store.store_shard(content_hash, 0, b"shard0").unwrap();
        store.store_shard(content_hash, 1, b"shard1").unwrap();

        assert!(store.has_shard(content_hash, 0));
        assert!(store.has_shard(content_hash, 1));

        store.delete_content(content_hash).unwrap();

        assert!(!store.has_shard(content_hash, 0));
        assert!(!store.has_shard(content_hash, 1));
    }

    #[test]
    fn shard_store_total_size() {
        let tmp = TempDir::new().unwrap();
        let store = ShardStore::new(tmp.path().to_path_buf()).unwrap();

        assert_eq!(store.total_size(), 0);

        store.store_shard("content1", 0, b"12345").unwrap();
        assert_eq!(store.total_size(), 5);

        store.store_shard("content1", 1, b"67890").unwrap();
        assert_eq!(store.total_size(), 10);

        store.store_shard("content2", 0, b"abc").unwrap();
        assert_eq!(store.total_size(), 13);
    }

    #[test]
    fn shard_store_list_content() {
        let tmp = TempDir::new().unwrap();
        let store = ShardStore::new(tmp.path().to_path_buf()).unwrap();

        assert!(store.list_content().is_empty());

        store.store_shard("content1", 0, b"data").unwrap();
        store.store_shard("content2", 0, b"data").unwrap();
        store.store_shard("content1", 1, b"data").unwrap();

        let content = store.list_content();
        assert_eq!(content.len(), 2);
        assert!(content.contains(&"content1".to_string()));
        assert!(content.contains(&"content2".to_string()));
    }

    #[test]
    fn shard_store_list_shards() {
        let tmp = TempDir::new().unwrap();
        let store = ShardStore::new(tmp.path().to_path_buf()).unwrap();

        let content_hash = "content_xyz";
        store.store_shard(content_hash, 0, b"shard0").unwrap();
        store.store_shard(content_hash, 2, b"shard2").unwrap();
        store.store_shard(content_hash, 5, b"shard5").unwrap();

        let shards = store.list_shards(content_hash);
        assert_eq!(shards, vec![0, 2, 5]);
    }

    #[test]
    fn shard_store_quarantine() {
        let tmp = TempDir::new().unwrap();
        let store = ShardStore::new(tmp.path().to_path_buf()).unwrap();

        let content_hash = "flagged_content";
        store.store_shard(content_hash, 0, b"bad").unwrap();
        store.store_shard(content_hash, 1, b"data").unwrap();

        assert!(store.has_shard(content_hash, 0));

        store.quarantine_content(content_hash).unwrap();

        // Content should no longer be in normal location
        assert!(!store.has_shard(content_hash, 0));

        // Should be in quarantine
        let quarantine_path = tmp.path()
            .join("shards")
            .join("quarantine")
            .join(content_hash)
            .join("0");
        assert!(quarantine_path.exists());

        // Size should reflect quarantined content
        assert!(store.quarantine_size() > 0);
    }

    #[test]
    fn shard_store_delete_quarantined() {
        let tmp = TempDir::new().unwrap();
        let store = ShardStore::new(tmp.path().to_path_buf()).unwrap();

        let content_hash = "to_delete";
        store.store_shard(content_hash, 0, b"data").unwrap();
        store.quarantine_content(content_hash).unwrap();

        assert!(store.quarantine_size() > 0);

        store.delete_quarantined(content_hash).unwrap();

        assert_eq!(store.quarantine_size(), 0);
    }

    #[test]
    fn shard_store_stats() {
        let tmp = TempDir::new().unwrap();
        let store = ShardStore::new(tmp.path().to_path_buf()).unwrap();

        store.store_shard("content1", 0, b"12345").unwrap();
        store.store_shard("content1", 1, b"67890").unwrap();
        store.store_shard("content2", 0, b"abc").unwrap();

        let stats = store.stats();
        assert_eq!(stats.total_bytes, 13);
        assert_eq!(stats.content_count, 2);
        assert_eq!(stats.shard_count, 3);
    }
}
