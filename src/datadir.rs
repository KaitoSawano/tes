// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! Data directory layout and path helpers.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::consensus::spec;

pub const BLOCKS_DIR: &str = "blocks";
pub const CHAINSTATE_DIR: &str = "chainstate";
pub const UNDO_DIR: &str = "undo";
pub const WALLET_FILE: &str = "wallet.dat";
pub const CONFIG_FILE: &str = "xepay.conf";
pub const PEERS_FILE: &str = "peers.json";
pub const MEMPOOL_FILE: &str = "mempool.json";
pub const DEBUG_LOG: &str = "debug.log";
pub const BLOCK_FILE_PREFIX: &str = "blk";
pub const PEER_ID_FILE: &str = "peer_id";
pub const COOKIE_FILE: &str = ".cookie";
pub const STATE_DB_DIR: &str = "state_db";

static LOG_MUTEX: Mutex<()> = Mutex::new(());

pub fn datadir() -> PathBuf {
    if let Ok(custom) = std::env::var("XEPC_DATADIR") {
        return PathBuf::from(custom);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(spec::current_network().datadir_name())
}

pub fn blocks_dir() -> PathBuf {
    datadir().join(BLOCKS_DIR)
}
pub fn chainstate_dir() -> PathBuf {
    datadir().join(CHAINSTATE_DIR)
}
pub fn undo_dir() -> PathBuf {
    datadir().join(UNDO_DIR)
}
pub fn undo_file(height: u64) -> PathBuf {
    undo_dir().join(format!("rev{:08}.bin", height))
}
pub fn state_db_path() -> PathBuf {
    chainstate_dir().join(STATE_DB_DIR)
}
pub fn wallet_path() -> PathBuf {
    datadir().join(WALLET_FILE)
}
pub fn config_path() -> PathBuf {
    datadir().join(CONFIG_FILE)
}
pub fn peers_path() -> PathBuf {
    datadir().join(PEERS_FILE)
}
pub fn mempool_path() -> PathBuf {
    datadir().join(MEMPOOL_FILE)
}
pub fn debug_log_path() -> PathBuf {
    datadir().join(DEBUG_LOG)
}
pub fn peer_id_path() -> PathBuf {
    datadir().join(PEER_ID_FILE)
}
pub fn cookie_path() -> PathBuf {
    datadir().join(COOKIE_FILE)
}

pub fn block_file(index: u32) -> PathBuf {
    blocks_dir().join(format!("{}{:05}.dat", BLOCK_FILE_PREFIX, index))
}

pub fn chainstate_file() -> PathBuf {
    chainstate_dir().join("state.json")
}

pub fn ensure_dirs() -> std::io::Result<()> {
    std::fs::create_dir_all(datadir())?;
    std::fs::create_dir_all(blocks_dir())?;
    std::fs::create_dir_all(chainstate_dir())?;
    std::fs::create_dir_all(state_db_path())?;
    std::fs::create_dir_all(undo_dir())?;
    Ok(())
}

pub fn exists() -> bool {
    datadir().exists()
}

pub fn as_str(p: &Path) -> String {
    p.to_string_lossy().to_string()
}

/// Best-effort fsync of a directory, so that a rename or a newly created
/// file inside it survives a power loss. Errors are ignored: some platforms
/// cannot open a directory for syncing.
pub fn sync_dir(dir: &Path) {
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
}

/// Best-effort fsync of the write-ahead log and manifest files of a LevelDB
/// directory. LevelDB's own "sync" write only hands the data to the OS; this
/// pushes it to the disk. Errors are ignored (the state is recoverable).
pub fn sync_leveldb_dir(dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".log") || name.starts_with("MANIFEST") || name == "CURRENT" {
                if let Ok(f) = std::fs::File::open(entry.path()) {
                    let _ = f.sync_all();
                }
            }
        }
    }
}

/// Replace `path` with `data` atomically and durably.
///
/// The data is written to `<path>.tmp`, synced to disk, and only then
/// renamed over the target, so a crash or a full disk can never leave a
/// truncated or half-written file behind: the reader sees either the old
/// file or the new one. With `private` set the file is created with mode
/// 0600 (owner only) on Unix, which is required for files holding keys.
pub fn write_atomic(path: &Path, data: &[u8], private: bool) -> std::io::Result<()> {
    use std::io::Write;

    let mut tmp_name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    tmp_name.push(".tmp");
    let tmp = path.with_file_name(tmp_name);

    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(if private { 0o600 } else { 0o644 });
        }
        let mut f = opts.open(&tmp)?;
        #[cfg(unix)]
        {
            // A stale temporary file may already exist with looser permissions.
            use std::os::unix::fs::PermissionsExt;
            if private {
                f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            }
        }
        #[cfg(not(unix))]
        let _ = private;
        f.write_all(data)?;
        f.sync_all()?;
    }

    std::fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent() {
        sync_dir(parent);
    }
    Ok(())
}

pub fn append_debug_log(line: &str) {
    let _guard = LOG_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _ = ensure_dirs();
    let path = debug_log_path();
    let ts = crate::utils::now_millis();
    let entry = format!("{} {}\n", ts, line);
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = f.write_all(entry.as_bytes());
    }
}
