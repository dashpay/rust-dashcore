use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use dashcore::consensus::{encode, Decodable};
use dashcore::Block;
use tokio::task::JoinSet;

use super::{Migrator, MigratorError};

const SEGMENT_PREFIX: &str = "segment";
const SEGMENT_EXTENSION: &str = "dat";

const LEGACY_SEGMENT_ID_DIGITS: usize = 4;
const LEGACY_ITEMS_PER_SEGMENT: u32 = 50_000;

const SEGMENT_ID_DIGITS: usize = 6;
const BLOCK_HEADERS_PER_SEGMENT: u32 = 10_000;
const FILTER_HEADERS_PER_SEGMENT: u32 = 50_000;
const FILTERS_PER_SEGMENT: u32 = 2_000;
const BLOCKS_PER_SEGMENT: u32 = 1_000;

const TMP_DIR: &str = "tmp";
const WORKERS_PER_FOLDER: usize = 4;

const BLOCK_HEADER_LEN: usize = 80;
const HASH_LEN: usize = 32;
const SENTINEL_VERSION: [u8; 4] = i32::MAX.to_le_bytes();

#[derive(Clone, Copy)]
enum ItemKind {
    BlockHeader,
    FilterHeader,
    Filter,
    Block,
}

const FOLDERS: [(&str, ItemKind, u32); 4] = [
    ("block_headers", ItemKind::BlockHeader, BLOCK_HEADERS_PER_SEGMENT),
    ("filter_headers", ItemKind::FilterHeader, FILTER_HEADERS_PER_SEGMENT),
    ("filters", ItemKind::Filter, FILTERS_PER_SEGMENT),
    ("blocks", ItemKind::Block, BLOCKS_PER_SEGMENT),
];

const _: () = {
    let mut i = 0;
    while i < FOLDERS.len() {
        assert!(LEGACY_ITEMS_PER_SEGMENT.is_multiple_of(FOLDERS[i].2));
        i += 1;
    }
};

pub struct V2Migrator;

#[async_trait]
impl Migrator for V2Migrator {
    async fn apply_migration(&self, storage_path: &Path) -> Result<(), MigratorError> {
        let tmp = storage_path.join(TMP_DIR);
        remove_dir_if_exists(&tmp).await?;

        let mut folders = JoinSet::new();
        for (name, kind, items_per_segment) in FOLDERS {
            folders.spawn(migrate_folder(
                storage_path.to_path_buf(),
                name,
                kind,
                items_per_segment,
            ));
        }
        while let Some(result) = folders.join_next().await {
            result.expect("folder migration panicked")?;
        }

        remove_dir_if_exists(&tmp).await?;

        Ok(())
    }
}

async fn remove_dir_if_exists(path: &Path) -> io::Result<()> {
    match tokio::fs::remove_dir_all(path).await {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

async fn migrate_folder(
    storage_path: PathBuf,
    name: &'static str,
    kind: ItemKind,
    items_per_segment: u32,
) -> Result<(), MigratorError> {
    let folder = storage_path.join(name);
    let staged = storage_path.join(TMP_DIR).join(name);

    let (legacy_ids, has_current) = segment_ids(&folder).await?;
    if legacy_ids.is_empty() {
        return Ok(());
    }
    if has_current {
        return Err(MigratorError::Corruption(format!(
            "{folder:?} holds both legacy and current segment files"
        )));
    }

    tokio::fs::create_dir_all(&staged).await?;

    let mut workers = JoinSet::new();
    for worker in 0..WORKERS_PER_FOLDER {
        let ids: Vec<u32> =
            legacy_ids.iter().skip(worker).step_by(WORKERS_PER_FOLDER).copied().collect();
        let (folder, staged) = (folder.clone(), staged.clone());
        workers.spawn_blocking(move || {
            ids.into_iter().try_for_each(|legacy_id| {
                split_segment(&folder, &staged, legacy_id, kind, items_per_segment)
            })
        });
    }
    while let Some(result) = workers.join_next().await {
        result.expect("migration worker panicked")?;
    }

    let mut staged_entries = tokio::fs::read_dir(&staged).await?;
    while let Some(entry) = staged_entries.next_entry().await? {
        tokio::fs::rename(entry.path(), folder.join(entry.file_name())).await?;
    }

    for legacy_id in legacy_ids {
        tokio::fs::remove_file(folder.join(legacy_segment_file_name(legacy_id))).await?;
    }

    Ok(())
}

async fn segment_ids(folder: &Path) -> Result<(Vec<u32>, bool), MigratorError> {
    let mut entries = match tokio::fs::read_dir(folder).await {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((Vec::new(), false)),
        Err(e) => return Err(e.into()),
    };

    let prefix = format!("{SEGMENT_PREFIX}_");
    let suffix = format!(".{SEGMENT_EXTENSION}");

    let mut legacy_ids = Vec::new();
    let mut has_current = false;
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name();
        let Some(digits) = name
            .to_str()
            .and_then(|name| name.strip_prefix(&prefix))
            .and_then(|rest| rest.strip_suffix(&suffix))
            .filter(|digits| digits.bytes().all(|b| b.is_ascii_digit()))
        else {
            continue;
        };
        match digits.len() {
            LEGACY_SEGMENT_ID_DIGITS => {
                legacy_ids.push(digits.parse().expect("four ascii digits fit in a u32"))
            }
            SEGMENT_ID_DIGITS => has_current = true,
            _ => {}
        }
    }
    legacy_ids.sort_unstable();

    Ok((legacy_ids, has_current))
}

fn split_segment(
    folder: &Path,
    staged: &Path,
    legacy_id: u32,
    kind: ItemKind,
    items_per_segment: u32,
) -> Result<(), MigratorError> {
    let legacy_path = folder.join(legacy_segment_file_name(legacy_id));
    let mut reader = BufReader::new(File::open(&legacy_path)?);

    let segments_per_legacy = LEGACY_ITEMS_PER_SEGMENT / items_per_segment;

    for chunk in 0..segments_per_legacy {
        let mut items = Vec::with_capacity(items_per_segment as usize);
        while items.len() < items_per_segment as usize {
            let Some(item) = read_item(&mut reader, kind)? else {
                break;
            };
            items.push(item);
        }

        if items.is_empty() {
            return Ok(());
        }

        if !items.iter().all(|item| is_sentinel(item, kind)) {
            let id = legacy_id * segments_per_legacy + chunk;
            write_segment(&staged.join(segment_file_name(id)), &items)?;
        }

        if items.len() < items_per_segment as usize {
            return Ok(());
        }
    }

    if read_item(&mut reader, kind)?.is_some() {
        return Err(MigratorError::Corruption(format!(
            "{legacy_path:?} holds more than {LEGACY_ITEMS_PER_SEGMENT} items"
        )));
    }

    Ok(())
}

fn legacy_segment_file_name(id: u32) -> String {
    format!("{SEGMENT_PREFIX}_{id:0width$}.{SEGMENT_EXTENSION}", width = LEGACY_SEGMENT_ID_DIGITS)
}

fn segment_file_name(id: u32) -> String {
    format!("{SEGMENT_PREFIX}_{id:0width$}.{SEGMENT_EXTENSION}", width = SEGMENT_ID_DIGITS)
}

fn write_segment(path: &Path, items: &[Vec<u8>]) -> Result<(), MigratorError> {
    let mut writer = BufWriter::new(File::create(path)?);
    for item in items {
        writer.write_all(item)?;
    }
    writer.into_inner().map_err(|e| e.into_error())?.sync_all()?;
    Ok(())
}

fn read_item<R: Read>(reader: &mut R, kind: ItemKind) -> Result<Option<Vec<u8>>, MigratorError> {
    let mut tee = Tee {
        inner: reader,
        bytes: Vec::new(),
    };

    let result = match kind {
        ItemKind::BlockHeader => read_fixed(&mut tee, BLOCK_HEADER_LEN + HASH_LEN),
        ItemKind::FilterHeader => read_fixed(&mut tee, HASH_LEN),
        ItemKind::Filter => Vec::<u8>::consensus_decode(&mut tee).map(drop),
        ItemKind::Block => read_fixed(&mut tee, HASH_LEN)
            .and_then(|()| Block::consensus_decode(&mut tee).map(drop)),
    };

    match result {
        Ok(()) => Ok(Some(tee.bytes)),
        Err(encode::Error::Io(e))
            if e.kind() == io::ErrorKind::UnexpectedEof && tee.bytes.is_empty() =>
        {
            Ok(None)
        }
        Err(e) => Err(MigratorError::Corruption(format!("Failed to decode legacy item: {e}"))),
    }
}

fn read_fixed<R: Read>(reader: &mut R, len: usize) -> Result<(), encode::Error> {
    let mut buf = vec![0; len];
    reader.read_exact(&mut buf)?;
    Ok(())
}

fn is_sentinel(item: &[u8], kind: ItemKind) -> bool {
    match kind {
        ItemKind::BlockHeader => item[..4] == SENTINEL_VERSION,
        ItemKind::FilterHeader => item == [0; HASH_LEN],
        ItemKind::Filter => item == [0],
        ItemKind::Block => item[HASH_LEN..HASH_LEN + 4] == SENTINEL_VERSION,
    }
}

struct Tee<'a, R> {
    inner: &'a mut R,
    bytes: Vec<u8>,
}

impl<R: Read> Read for Tee<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.bytes.extend_from_slice(&buf[..n]);
        Ok(n)
    }
}
