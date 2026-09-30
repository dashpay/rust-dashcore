use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::Path;

use async_trait::async_trait;
use dashcore::consensus::{encode, Decodable};
use dashcore::Block;

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
        remove_dir_if_exists(&tmp)?;

        for (folder, kind, items_per_segment) in FOLDERS {
            migrate_folder(storage_path, folder, kind, items_per_segment)?;
        }

        remove_dir_if_exists(&tmp)?;

        Ok(())
    }
}

fn remove_dir_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_dir_all(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

fn migrate_folder(
    storage_path: &Path,
    name: &str,
    kind: ItemKind,
    items_per_segment: u32,
) -> Result<(), MigratorError> {
    let folder = storage_path.join(name);
    let staged = storage_path.join(TMP_DIR).join(name);

    let legacy_ids = legacy_segment_ids(&folder)?;
    if legacy_ids.is_empty() {
        return Ok(());
    }

    remove_dir_if_exists(&staged)?;
    fs::create_dir_all(&staged)?;

    for &legacy_id in &legacy_ids {
        split_segment(&folder, &staged, legacy_id, kind, items_per_segment)?;
    }

    for entry in fs::read_dir(&staged)? {
        let entry = entry?;
        fs::rename(entry.path(), folder.join(entry.file_name()))?;
    }

    for legacy_id in legacy_ids {
        fs::remove_file(folder.join(legacy_segment_file_name(legacy_id)))?;
    }

    remove_dir_if_exists(&staged)?;

    Ok(())
}

fn legacy_segment_ids(folder: &Path) -> Result<Vec<u32>, MigratorError> {
    let entries = match fs::read_dir(folder) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };

    let prefix = format!("{SEGMENT_PREFIX}_");
    let suffix = format!(".{SEGMENT_EXTENSION}");

    let mut ids = Vec::new();
    for entry in entries {
        let name = entry?.file_name();
        let Some(digits) = name
            .to_str()
            .and_then(|name| name.strip_prefix(&prefix))
            .and_then(|rest| rest.strip_suffix(&suffix))
        else {
            continue;
        };
        if digits.len() == LEGACY_SEGMENT_ID_DIGITS && digits.bytes().all(|b| b.is_ascii_digit()) {
            ids.push(digits.parse().expect("four ascii digits fit in a u32"));
        }
    }
    ids.sort_unstable();

    Ok(ids)
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
        Err(encode::Error::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
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
