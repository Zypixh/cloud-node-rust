use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use http::HeaderMap;
use pingora_cache::CacheMeta;
use pingora_cache::storage::HitHandler;
use pingora_http::ResponseHeader;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::{Mutex, OwnedMutexGuard};

pub const PARTIAL_KEY_PREFIX: &str = "__cloud_node_partial:";
pub const MIN_FORCE_PARTIAL_HIT_BYTES: u64 = 256 * 1024;
/// Upper bound for a sparse partial object.  Without this limit a forged or
/// malformed Content-Range can make the cache seek/create a multi-exabyte
/// sparse file and exhaust inode/disk quotas.
pub const MAX_PARTIAL_OBJECT_BYTES: u64 = 1 << 40;
static PARTIAL_TEMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[derive(Clone, Debug)]
pub struct PartialCapture {
    pub start: u64,
    pub end: u64,
    pub total: Option<u64>,
    pub expires: i64,
    pub headers: Vec<(String, String)>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub created_at: i64,
    pub min_size: Option<i64>,
    pub max_size: Option<i64>,
}

pub struct PartialWriter {
    root_key: String,
    capture: PartialCapture,
    file: Option<tokio::fs::File>,
    temp_path: PathBuf,
    written: u64,
    committed: bool,
    purge_generation: u64,
    _purge_guard: tokio::sync::OwnedRwLockReadGuard<()>,
    _root_guard: OwnedMutexGuard<()>,
    _process_lock: Option<crate::cache_hybrid::CacheProcessLockGuard>,
}

pub struct PartialHit {
    pub meta: CacheMeta,
    pub handler: HitHandler,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ContentRange {
    pub start: u64,
    pub end: u64,
    pub total: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
pub struct RequestedRange {
    start: Option<u64>,
    end: Option<u64>,
    suffix_len: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredRange {
    start: u64,
    end: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PartialMeta {
    #[serde(default)]
    root_key: String,
    #[serde(default)]
    root_path: Option<String>,
    total_size: Option<u64>,
    expires: i64,
    headers: Vec<(String, String)>,
    ranges: Vec<StoredRange>,
    #[serde(default)]
    etag: Option<String>,
    #[serde(default)]
    last_modified: Option<String>,
    #[serde(default)]
    created_at: i64,
    /// Generation of the immutable body file referenced by this metadata.
    /// Zero is the legacy `<hash>.body` format.
    #[serde(default)]
    body_generation: u64,
}

struct LoadedPartialMeta {
    meta: PartialMeta,
    root: PathBuf,
}

pub fn partial_cache_key(base_key: &str, range_header: Option<&str>) -> Option<String> {
    let selector = match range_header {
        Some(range_header) => {
            parse_single_range_header(range_header)?;
            URL_SAFE_NO_PAD.encode(range_header.as_bytes())
        }
        None => "force".to_string(),
    };
    let encoded_base = URL_SAFE_NO_PAD.encode(base_key.as_bytes());
    let mut key =
        String::with_capacity(PARTIAL_KEY_PREFIX.len() + encoded_base.len() + selector.len() + 1);
    key.push_str(PARTIAL_KEY_PREFIX);
    key.push_str(&encoded_base);
    key.push(':');
    key.push_str(&selector);
    Some(key)
}

pub fn is_partial_cache_key(cache_key: &str) -> bool {
    split_partial_cache_key(cache_key).is_some()
}

fn lock_for(cache_key: &str) -> Arc<Mutex<()>> {
    crate::cache_hybrid::cache_write_lock_for_key(cache_key)
}

pub fn parse_single_range_header(value: &str) -> Option<RequestedRange> {
    let value = value.trim();
    let spec = value
        .get(..6)
        .filter(|prefix| prefix.eq_ignore_ascii_case("bytes="))
        .and_then(|_| value.get(6..))?
        .trim();
    if spec.is_empty() || spec.contains(',') {
        return None;
    }

    let (start, end) = spec.split_once('-')?;
    let start = start.trim();
    let end = end.trim();
    if start.is_empty() {
        let suffix_len = end
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0 && *value <= MAX_PARTIAL_OBJECT_BYTES)?;
        return Some(RequestedRange {
            start: None,
            end: None,
            suffix_len: Some(suffix_len),
        });
    }

    let start = start.parse::<u64>().ok()?;
    let end = if end.is_empty() {
        None
    } else {
        Some(end.parse::<u64>().ok()?)
    };
    if end.is_some_and(|end| end < start) {
        return None;
    }
    if start >= MAX_PARTIAL_OBJECT_BYTES || end.is_some_and(|end| end >= MAX_PARTIAL_OBJECT_BYTES) {
        return None;
    }

    Some(RequestedRange {
        start: Some(start),
        end,
        suffix_len: None,
    })
}

pub fn parse_content_range(value: &str) -> Option<ContentRange> {
    let value = value.trim();
    let value = value
        .get(..6)
        .filter(|prefix| prefix.eq_ignore_ascii_case("bytes "))
        .and_then(|_| value.get(6..))?;
    let (range, total) = value.split_once('/')?;
    let (start, end) = range.split_once('-')?;
    let start = start.trim().parse::<u64>().ok()?;
    let end = end.trim().parse::<u64>().ok()?;
    if end < start {
        return None;
    }
    if start >= MAX_PARTIAL_OBJECT_BYTES || end >= MAX_PARTIAL_OBJECT_BYTES {
        return None;
    }
    let total = total.trim().parse::<u64>().ok().filter(|total| *total > 0);
    if total.is_some_and(|total| total > MAX_PARTIAL_OBJECT_BYTES || end >= total) {
        return None;
    }
    Some(ContentRange { start, end, total })
}

pub fn content_range_from_headers(headers: &HeaderMap) -> Option<ContentRange> {
    let mut parsed = None;
    for value in headers.get_all("content-range").iter() {
        let value = value.to_str().ok()?;
        let current = parse_content_range(value)?;
        if parsed.as_ref().is_some_and(|previous| previous != &current) {
            return None;
        }
        parsed = Some(current);
    }
    parsed
}

/// Verify that an origin Content-Range is the representation requested by a
/// partial cache key. Origin servers are allowed to clip an explicit end to
/// the selected representation's length, and suffix ranges must be resolved
/// against that same length. Anything else would publish bytes under a key
/// that promises a different range.
pub fn content_range_matches_cache_key(cache_key: &str, actual: &ContentRange) -> bool {
    let Some((_, Some(requested_header))) = split_partial_cache_key(cache_key) else {
        return false;
    };
    content_range_matches_request(&requested_header, actual)
}

fn content_range_matches_request(requested_header: &str, actual: &ContentRange) -> bool {
    let Some(total) = actual.total else {
        return false;
    };
    if total == 0 || actual.start > actual.end || actual.end >= total {
        return false;
    }
    let Some(requested) = parse_single_range_header(requested_header) else {
        return false;
    };
    let (expected_start, expected_end) = if let Some(suffix_len) = requested.suffix_len {
        let length = suffix_len.min(total);
        (total - length, total - 1)
    } else {
        let Some(start) = requested.start else {
            return false;
        };
        if start >= total {
            return false;
        }
        let requested_end = requested.end.unwrap_or(total - 1);
        (start, requested_end.min(total - 1))
    };
    actual.start == expected_start && actual.end == expected_end
}

pub fn response_headers_to_store(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            let name_s = name.as_str();
            if !crate::cache::should_store_response_header(name_s) {
                return None;
            }
            Some((
                name_s.to_ascii_lowercase(),
                value.to_str().ok()?.to_string(),
            ))
        })
        .collect()
}

pub async fn lookup(cache_key: &str, roots: &[PathBuf]) -> std::io::Result<Option<PartialHit>> {
    let Some((root_key, range_header)) = split_partial_cache_key(cache_key) else {
        return Ok(None);
    };
    let root_key = root_key.as_str();
    // The body is versioned and immutable after publication, but the metadata
    // and body must still be selected as one pair. Keep the root-key lock
    // until the hit handler is dropped so a purge or a body-version switch
    // cannot race an open/read sequence.
    // Broad purges take the write side before scanning all roots. Acquire the
    // read side first so a lookup that starts after such a purge has begun
    // cannot open and return the old body while the scan is in progress.
    let purge_guard = crate::cache_hybrid::acquire_cache_purge_read_guard().await;
    let root_guard = lock_for(root_key).lock_owned().await;
    let process_lock =
        match crate::cache_hybrid::acquire_cache_process_read_lock(root_key, roots).await {
            Ok(lock) => lock,
            Err(err) => {
                tracing::warn!(
                    cache_key,
                    error = %err,
                    "CACHE_PARTIAL_HIT: unable to acquire cross-process cache lock; bypassing cache"
                );
                return Ok(None);
            }
        };
    let Some(LoadedPartialMeta {
        mut meta,
        root: metadata_root,
    }) = load_meta_with_root(root_key, roots).await?
    else {
        return Ok(None);
    };

    if !partial_meta_bounds_are_valid(&meta)
        || !crate::cache::stored_response_headers_allow_shared_cache(&meta.headers)
        || !crate::cache::stored_response_encoding_matches_cache_key(cache_key, &meta.headers)
    {
        remove_locked(root_key, roots).await;
        return Ok(None);
    }

    let now = crate::utils::time::now_timestamp();
    if meta.expires <= now {
        remove_locked(root_key, roots).await;
        return Ok(None);
    }

    normalize_ranges(&mut meta.ranges);
    if let Some(total) = meta.total_size {
        if total == 0 {
            return Ok(None);
        }
        meta.ranges.retain(|range| range.end < total);
    }
    // A partial object is only a valid response to an explicit client Range
    // request. Older code had a "force" selector that could replay an
    // arbitrary stored chunk as a 206 for an ordinary full-object request.
    let Some(range_header) = range_header.as_deref() else {
        return Ok(None);
    };
    let Some(requested) = parse_single_range_header(range_header) else {
        return Ok(None);
    };
    let selected = select_requested_range(&meta, requested);

    let Some((start, end)) = selected else {
        return Ok(None);
    };
    let Some(stored) = meta
        .ranges
        .iter()
        .find(|range| range.start <= start && range.end >= end)
    else {
        return Ok(None);
    };
    if stored.end < stored.start {
        return Ok(None);
    }
    let Some(len) = end.checked_sub(start).and_then(|len| len.checked_add(1)) else {
        return Ok(None);
    };
    let Some(end_exclusive) = start.checked_add(len) else {
        return Ok(None);
    };
    let existing_data_path = body_path_in_root(root_key, &metadata_root, meta.body_generation);
    let mut file = match tokio::fs::File::open(existing_data_path).await {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    file.seek(std::io::SeekFrom::Start(start)).await?;
    let file_len = file
        .metadata()
        .await
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    if file_len < end_exclusive {
        return Ok(None);
    }

    let mut header = ResponseHeader::build(206, Some(meta.headers.len() + 3)).unwrap();
    for (name, value) in meta.headers.iter() {
        let name = name.clone();
        let value = value.clone();
        let _ = header.append_header(name, value);
    }
    let total = meta
        .total_size
        .map(|total| total.to_string())
        .unwrap_or_else(|| "*".to_string());
    let _ = header.insert_header(
        "content-range",
        format!("bytes {}-{}/{}", start, end, total),
    );
    let _ = header.insert_header("content-length", len.to_string());
    let _ = header.insert_header("accept-ranges", "bytes");

    let meta = CacheMeta::new(
        system_time_from_timestamp(meta.expires),
        system_time_from_timestamp(if meta.created_at > 0 {
            meta.created_at
        } else {
            now
        }),
        0,
        0,
        header,
    );
    Ok(Some(PartialHit {
        meta,
        handler: Box::new(PartialFileHitHandler {
            file: Some(file),
            remaining: len,
            buf_size: 128 * 1024,
            cache_key: root_key.to_string(),
            roots: roots.to_vec(),
            invalidated: false,
            _purge_guard: purge_guard,
            _root_guard: root_guard,
            _process_lock: Some(process_lock),
        }),
    }))
}

pub async fn open_writer(
    cache_key: &str,
    capture: PartialCapture,
    roots: &[PathBuf],
    write_root: PathBuf,
) -> std::io::Result<Option<PartialWriter>> {
    open_writer_with_generation(cache_key, capture, roots, write_root, None).await
}

/// Opens a range writer while fencing it to the purge generation observed by
/// the request. Direct callers can leave the generation unset; the proxy miss
/// path supplies the generation captured before it waited for the key lock.
pub async fn open_writer_with_generation(
    cache_key: &str,
    capture: PartialCapture,
    _roots: &[PathBuf],
    write_root: PathBuf,
    expected_generation: Option<u64>,
) -> std::io::Result<Option<PartialWriter>> {
    let root_key = partial_root_key(cache_key);
    let root_key = root_key.as_ref();
    if !capture_allows_store(&capture, None)
        || !crate::cache::stored_response_headers_allow_shared_cache(&capture.headers)
        || !crate::cache::stored_response_encoding_matches_cache_key(cache_key, &capture.headers)
    {
        return Ok(None);
    }

    // Hold the purge read guard and root-key lock for the entire lifetime of
    // the writer. The previous implementation released them after opening
    // the shared sparse body, allowing two range fills (or a purge) to modify
    // or republish the same bytes while metadata still advertised them as
    // complete.
    let purge_guard = crate::cache_hybrid::acquire_cache_purge_read_guard().await;
    let root_guard = lock_for(root_key).lock_owned().await;
    let process_lock =
        match crate::cache_hybrid::acquire_cache_process_read_lock(root_key, _roots).await {
            Ok(lock) => lock,
            Err(err) => {
                tracing::warn!(
                    cache_key,
                    error = %err,
                    "CACHE_PARTIAL_MISS: unable to acquire cross-process cache lock; bypassing fill"
                );
                return Ok(None);
            }
        };
    open_writer_with_guards(
        cache_key,
        capture,
        write_root,
        expected_generation,
        purge_guard,
        root_guard,
        Some(process_lock),
    )
    .await
}

/// Opens a range writer with guards that were acquired by the miss handler.
/// A partial miss must acquire these guards when the handler is created, not
/// only when its first body chunk arrives: a purge may otherwise complete in
/// the gap and an old origin response could be published afterwards.
pub(crate) async fn open_writer_with_guards(
    cache_key: &str,
    capture: PartialCapture,
    write_root: PathBuf,
    expected_generation: Option<u64>,
    purge_guard: tokio::sync::OwnedRwLockReadGuard<()>,
    root_guard: OwnedMutexGuard<()>,
    process_lock: Option<crate::cache_hybrid::CacheProcessLockGuard>,
) -> std::io::Result<Option<PartialWriter>> {
    let root_key = partial_root_key(cache_key);
    let root_key = root_key.as_ref();
    if !capture_allows_store(&capture, None)
        || !crate::cache::stored_response_headers_allow_shared_cache(&capture.headers)
        || !crate::cache::stored_response_encoding_matches_cache_key(cache_key, &capture.headers)
    {
        return Ok(None);
    }

    let purge_generation = crate::cache_hybrid::current_cache_purge_generation();
    if expected_generation.is_some_and(|expected| expected != purge_generation) {
        return Ok(None);
    }
    let temp_path = partial_temp_path(root_key, &write_root, "range");
    if let Some(parent) = temp_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let file = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp_path)
        .await?;

    Ok(Some(PartialWriter {
        root_key: root_key.to_string(),
        capture,
        file: Some(file),
        temp_path,
        written: 0,
        committed: false,
        purge_generation,
        _purge_guard: purge_guard,
        _root_guard: root_guard,
        _process_lock: process_lock,
    }))
}

impl PartialWriter {
    pub async fn write(&mut self, data: &[u8]) -> std::io::Result<bool> {
        if data.is_empty() {
            return Ok(true);
        }
        let Some(expected_len) = capture_len(&self.capture) else {
            return Ok(false);
        };
        if self.written.saturating_add(data.len() as u64) > expected_len {
            return Ok(false);
        }
        let Some(file) = self.file.as_mut() else {
            return Ok(false);
        };
        file.write_all(data).await?;
        self.written += data.len() as u64;
        Ok(true)
    }

    pub async fn finish(mut self, roots: &[PathBuf], write_root: PathBuf) -> std::io::Result<bool> {
        if self.purge_generation != crate::cache_hybrid::current_cache_purge_generation() {
            return Ok(false);
        }
        if let Some(file) = self.file.as_mut() {
            file.flush().await?;
            file.sync_data().await?;
        }
        if capture_len(&self.capture).is_none_or(|expected| self.written != expected) {
            return Ok(false);
        }
        if self.purge_generation != crate::cache_hybrid::current_cache_purge_generation() {
            return Ok(false);
        }
        // Close the range temp before the commit so Windows can rename/delete
        // it as well as Unix.
        self.file.take();
        let committed = commit_range_locked(
            &self.root_key,
            &self.capture,
            roots,
            &write_root,
            &self.temp_path,
        )
        .await?;
        if committed {
            self.committed = true;
            let _ = tokio::fs::remove_file(&self.temp_path).await;
        }
        Ok(committed)
    }
}

impl Drop for PartialWriter {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        self.file.take();
        let temp_path = self.temp_path.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = tokio::fs::remove_file(temp_path).await;
            });
        } else {
            let _ = std::fs::remove_file(temp_path);
        }
    }
}

fn capture_len(capture: &PartialCapture) -> Option<u64> {
    capture.end.checked_sub(capture.start)?.checked_add(1)
}

fn capture_allows_store(capture: &PartialCapture, body_len: Option<u64>) -> bool {
    let Some(expected_len) = capture_len(capture) else {
        return false;
    };
    if capture.start >= MAX_PARTIAL_OBJECT_BYTES
        || capture.end >= MAX_PARTIAL_OBJECT_BYTES
        || expected_len > MAX_PARTIAL_OBJECT_BYTES
    {
        return false;
    }
    if capture.expires <= crate::utils::time::now_timestamp() {
        return false;
    }
    if body_len.is_some_and(|len| len != expected_len) {
        return false;
    }
    if let Some(total) = capture.total {
        if total == 0
            || total > MAX_PARTIAL_OBJECT_BYTES
            || capture.end >= total
            || total < MIN_FORCE_PARTIAL_HIT_BYTES
        {
            return false;
        }
        if let Some(min_size) = capture.min_size
            && min_size > 0
            && total < min_size as u64
        {
            return false;
        }
        if let Some(max_size) = capture.max_size
            && max_size > 0
            && total > max_size as u64
        {
            return false;
        }
    }
    true
}

pub async fn store(
    cache_key: &str,
    capture: &PartialCapture,
    body: &[u8],
    roots: &[PathBuf],
    write_root: PathBuf,
) -> std::io::Result<bool> {
    let Some(mut writer) =
        open_writer(cache_key, capture.clone(), roots, write_root.clone()).await?
    else {
        return Ok(false);
    };
    if !writer.write(body).await? {
        return Ok(false);
    }
    writer.finish(roots, write_root).await
}

fn validators_match(meta: &PartialMeta, capture: &PartialCapture) -> bool {
    match (&meta.etag, &capture.etag) {
        (Some(existing), Some(incoming)) => existing == incoming,
        (None, None) => match (&meta.last_modified, &capture.last_modified) {
            (Some(existing), Some(incoming)) => existing == incoming,
            _ => false,
        },
        _ => false,
    }
}

fn next_body_generation(previous: u64) -> u64 {
    // The partial directory may be shared by more than one worker process.
    // A process-local counter can then reuse a generation and make one
    // process's manifest point at another process's body. Use random bits for
    // the filename identity and retain monotonicity relative to the manifest
    // currently being merged.
    let uuid = uuid::Uuid::new_v4();
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&uuid.as_bytes()[..8]);
    let generated = u64::from_be_bytes(bytes);
    generated.max(previous.saturating_add(1)).max(1)
}

/// Commit one completed range as a new immutable body version. The caller
/// owns the root-key lock, so readers can never observe a body while it is
/// being copied/patched and metadata still points at the previous version.
async fn commit_range_locked(
    root_key: &str,
    capture: &PartialCapture,
    roots: &[PathBuf],
    write_root: &Path,
    range_temp_path: &Path,
) -> std::io::Result<bool> {
    let Some(expected_len) = capture_len(capture) else {
        return Ok(false);
    };
    if !capture_allows_store(capture, Some(expected_len)) {
        return Ok(false);
    }

    let now = crate::utils::time::now_timestamp();
    let loaded = load_meta_with_root(root_key, roots).await?;
    let metadata_can_merge = loaded.as_ref().is_some_and(|loaded| {
        crate::cache::stored_response_headers_allow_shared_cache(&loaded.meta.headers)
            && crate::cache::stored_response_encoding_matches_cache_key(
                root_key,
                &loaded.meta.headers,
            )
            && loaded.meta.expires > now
            && loaded.meta.total_size == capture.total
            && validators_match(&loaded.meta, capture)
    });
    let existing_body_path = loaded.as_ref().and_then(|loaded| {
        metadata_can_merge
            .then(|| body_path_in_root(root_key, &loaded.root, loaded.meta.body_generation))
    });
    let can_merge = if let Some(path) = existing_body_path.as_ref() {
        let required_len = loaded
            .as_ref()
            .map(|loaded| required_body_len(&loaded.meta))
            .unwrap_or(0);
        tokio::fs::metadata(path)
            .await
            .map(|metadata| metadata.len() >= required_len)
            .unwrap_or(false)
    } else {
        false
    };

    let target_root = if can_merge {
        loaded
            .as_ref()
            .map(|loaded| loaded.root.clone())
            .unwrap_or_else(|| write_root.to_path_buf())
    } else {
        write_root.to_path_buf()
    };
    let previous_generation = if can_merge {
        loaded
            .as_ref()
            .map(|loaded| loaded.meta.body_generation)
            .unwrap_or(0)
    } else {
        0
    };
    let new_generation = next_body_generation(previous_generation);
    let new_body_path = body_path_in_root(root_key, &target_root, new_generation);
    if let Some(parent) = new_body_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let new_body_temp_path = partial_temp_path(root_key, &target_root, "body");
    if can_merge {
        if let Err(err) = tokio::fs::copy(
            existing_body_path.as_ref().expect("merge body path"),
            &new_body_temp_path,
        )
        .await
        {
            let _ = tokio::fs::remove_file(&new_body_temp_path).await;
            return Err(err);
        }
    } else {
        if let Err(err) = tokio::fs::File::create(&new_body_temp_path).await {
            let _ = tokio::fs::remove_file(&new_body_temp_path).await;
            return Err(err);
        }
    }

    let body_result = async {
        let mut body_file = tokio::fs::OpenOptions::new()
            .write(true)
            .open(&new_body_temp_path)
            .await?;
        let end_exclusive = capture.end.checked_add(1).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "range overflow")
        })?;
        let required_len = capture.total.unwrap_or(0).max(end_exclusive);
        if body_file.metadata().await?.len() < required_len {
            body_file.set_len(required_len).await?;
        }
        body_file
            .seek(std::io::SeekFrom::Start(capture.start))
            .await?;
        let mut range_file = tokio::fs::File::open(range_temp_path).await?;
        let copied = tokio::io::copy(&mut range_file, &mut body_file).await?;
        if copied != expected_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "partial range temp is shorter than metadata",
            ));
        }
        body_file.flush().await?;
        body_file.sync_data().await?;
        Ok::<(), std::io::Error>(())
    }
    .await;
    if let Err(err) = body_result {
        let _ = tokio::fs::remove_file(&new_body_temp_path).await;
        return Err(err);
    }
    if let Err(err) = tokio::fs::rename(&new_body_temp_path, &new_body_path).await {
        let _ = tokio::fs::remove_file(&new_body_temp_path).await;
        return Err(err);
    }

    let mut meta = if can_merge {
        loaded
            .as_ref()
            .map(|loaded| loaded.meta.clone())
            .expect("merge metadata")
    } else {
        PartialMeta {
            root_key: root_key.to_string(),
            root_path: None,
            total_size: capture.total,
            expires: capture.expires,
            headers: capture.headers.clone(),
            ranges: Vec::new(),
            etag: capture.etag.clone(),
            last_modified: capture.last_modified.clone(),
            created_at: capture.created_at,
            body_generation: 0,
        }
    };
    meta.root_key = root_key.to_string();
    meta.root_path = Some(target_root.to_string_lossy().into_owned());
    meta.total_size = capture.total.or(meta.total_size);
    meta.expires = if can_merge {
        meta.expires.max(capture.expires)
    } else {
        capture.expires
    };
    if !capture.headers.is_empty() {
        meta.headers = capture.headers.clone();
    }
    meta.etag = capture.etag.clone();
    meta.last_modified = capture.last_modified.clone();
    meta.created_at = if can_merge && meta.created_at > 0 {
        meta.created_at
    } else if capture.created_at > 0 {
        capture.created_at
    } else {
        now
    };
    meta.body_generation = new_generation;
    meta.ranges.push(StoredRange {
        start: capture.start,
        end: capture.end,
    });
    normalize_ranges(&mut meta.ranges);
    if let Some(total) = meta.total_size {
        meta.ranges.retain(|range| range.end < total);
    }

    // If configuration changed roots and the old version cannot be merged,
    // remove the old manifest before publishing the new one. This avoids a
    // restart selecting the old root first if a crash occurs mid-switch.
    if !can_merge
        && let Some(loaded) = loaded.as_ref()
        && loaded.root != target_root
        && !remove_files_at_root(root_key, &loaded.root).await
    {
        // Do not publish a new-root manifest while the old manifest may still
        // be selected first after a restart. Keeping the old entry is safer
        // than exposing an ambiguous pair of manifests.
        let _ = tokio::fs::remove_file(&new_body_path).await;
        return Ok(false);
    }

    let meta_path = meta_path_in_root(root_key, &target_root);
    if let Some(parent) = meta_path.parent()
        && let Err(err) = tokio::fs::create_dir_all(parent).await
    {
        let _ = tokio::fs::remove_file(&new_body_path).await;
        return Err(err);
    }
    let meta_json = match serde_json::to_vec(&meta) {
        Ok(meta_json) => meta_json,
        Err(err) => {
            let _ = tokio::fs::remove_file(&new_body_path).await;
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, err));
        }
    };
    let meta_temp_path = partial_temp_path(root_key, &target_root, "meta");
    if let Err(err) = tokio::fs::write(&meta_temp_path, meta_json).await {
        let _ = tokio::fs::remove_file(&meta_temp_path).await;
        let _ = tokio::fs::remove_file(&new_body_path).await;
        return Err(err);
    }
    if let Err(err) = tokio::fs::rename(&meta_temp_path, &meta_path).await {
        let _ = tokio::fs::remove_file(&meta_temp_path).await;
        let _ = tokio::fs::remove_file(&new_body_path).await;
        return Err(err);
    }

    if let Some(old_body_path) = existing_body_path {
        if old_body_path != new_body_path {
            let _ = tokio::fs::remove_file(old_body_path).await;
        }
    } else if let Some(loaded) = loaded.as_ref()
        && loaded.root == target_root
    {
        let old_body_path = body_path_in_root(root_key, &loaded.root, loaded.meta.body_generation);
        if old_body_path != new_body_path {
            let _ = tokio::fs::remove_file(old_body_path).await;
        }
    }

    Ok(true)
}

pub async fn purge(cache_key: &str, roots: &[PathBuf]) {
    let root_key = partial_root_key(cache_key);
    let _guard = lock_for(root_key.as_ref()).lock_owned().await;
    remove_locked(root_key.as_ref(), roots).await;
}

/// Removes the aggregate entry while the caller already owns the canonical
/// resource lock. This is used by the full-cache purge path to avoid locking
/// the same key twice.
pub(crate) async fn purge_locked(cache_key: &str, roots: &[PathBuf]) {
    let root_key = partial_root_key(cache_key);
    remove_locked(root_key.as_ref(), roots).await;
}

pub async fn purge_prefix(prefix: &str, roots: &[PathBuf]) -> usize {
    let clean_prefix = prefix.trim_end_matches('*');
    let root_keys = collect_matching_root_keys(roots, |meta| {
        !meta.root_key.is_empty() && meta.root_key.starts_with(clean_prefix)
    })
    .await;
    let removed = root_keys.len();
    for root_key in root_keys {
        remove(&root_key, roots).await;
    }
    removed
}

pub async fn purge_by_tag(tag: &str, roots: &[PathBuf]) -> usize {
    let root_keys = collect_matching_root_keys(roots, |meta| {
        meta.headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("surrogate-key"))
            .map(|(_, value)| value.split_whitespace().any(|candidate| candidate == tag))
            .unwrap_or(false)
    })
    .await;
    let removed = root_keys.len();
    for root_key in root_keys {
        remove(&root_key, roots).await;
    }
    removed
}

async fn load_meta_with_root(
    cache_key: &str,
    roots: &[PathBuf],
) -> std::io::Result<Option<LoadedPartialMeta>> {
    // More than one configured root can contain a stale copy while a cache
    // directory is being migrated. Validate each manifest against the root it
    // was found in before deciding that the key is absent; returning `None`
    // for the first mismatched copy would hide a valid copy in a later root.
    for root in roots {
        let path = meta_path_in_root(cache_key, root);
        let data = match tokio::fs::read(&path).await {
            Ok(data) => data,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                tracing::warn!(
                    cache_key,
                    root = %root.display(),
                    error = %err,
                    "ignoring unreadable partial-cache metadata"
                );
                continue;
            }
        };
        let mut meta: PartialMeta = match serde_json::from_slice(&data) {
            Ok(meta) => meta,
            Err(err) => {
                tracing::warn!(
                    cache_key,
                    root = %root.display(),
                    error = %err,
                    "ignoring corrupt partial-cache metadata"
                );
                continue;
            }
        };
        if meta.root_key.is_empty() {
            meta.root_key = cache_key.to_string();
        }
        if meta.root_key != cache_key {
            tracing::warn!(
                cache_key,
                root = %root.display(),
                stored_root_key = %meta.root_key,
                "ignoring partial-cache metadata with mismatched root key"
            );
            continue;
        }
        if let Some(stored_root) = meta.root_path.as_deref()
            && Path::new(stored_root) != root
        {
            tracing::warn!(
                cache_key,
                stored_root,
                actual_root = %root.display(),
                "ignoring partial-cache metadata with mismatched root path"
            );
            continue;
        }
        meta.root_path = Some(root.to_string_lossy().into_owned());
        if !partial_meta_bounds_are_valid(&meta) {
            tracing::warn!(
                cache_key,
                root = %root.display(),
                "ignoring partial-cache metadata outside configured size bounds"
            );
            continue;
        }
        let body_path = body_path_in_root(cache_key, root, meta.body_generation);
        let body_len = match tokio::fs::metadata(&body_path).await {
            Ok(metadata) => metadata.len(),
            Err(err) => {
                // A stale or temporarily unreadable manifest in one root
                // must not hide a complete manifest in a later root
                // during migration or re-sharding.
                tracing::warn!(
                    cache_key,
                    root = %root.display(),
                    error = %err,
                    "ignoring partial-cache metadata whose body is unavailable"
                );
                continue;
            }
        };
        let required_len = required_body_len(&meta);
        if body_len < required_len {
            tracing::warn!(
                cache_key,
                root = %root.display(),
                body_len,
                required_len,
                "ignoring partial-cache metadata whose body is truncated"
            );
            continue;
        }
        return Ok(Some(LoadedPartialMeta {
            meta,
            root: root.clone(),
        }));
    }
    Ok(None)
}

fn partial_meta_bounds_are_valid(meta: &PartialMeta) -> bool {
    if meta
        .total_size
        .is_some_and(|total| total == 0 || total > MAX_PARTIAL_OBJECT_BYTES)
    {
        return false;
    }
    meta.ranges.iter().all(|range| {
        range.start <= range.end
            && range.start < MAX_PARTIAL_OBJECT_BYTES
            && range.end < MAX_PARTIAL_OBJECT_BYTES
            && meta.total_size.is_none_or(|total| range.end < total)
    })
}

async fn remove(cache_key: &str, roots: &[PathBuf]) {
    let _guard = lock_for(cache_key).lock_owned().await;
    remove_locked(cache_key, roots).await;
}

async fn remove_locked(cache_key: &str, roots: &[PathBuf]) {
    for root in roots {
        let _ = remove_files_at_root(cache_key, root).await;
    }
}

async fn remove_files_at_root(cache_key: &str, root: &Path) -> bool {
    let dir = partial_dir_in_root(cache_key, root);
    let hash = partial_hash(cache_key);
    let mut entries = match tokio::fs::read_dir(&dir).await {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return true,
        Err(err) => {
            tracing::warn!(
                cache_key,
                root = %root.display(),
                error = %err,
                "failed to open partial-cache directory during cleanup"
            );
            return false;
        }
    };
    let mut success = true;
    loop {
        let entry = match entries.next_entry().await {
            Ok(Some(entry)) => entry,
            Ok(None) => break,
            Err(err) => {
                tracing::warn!(
                    cache_key,
                    root = %root.display(),
                    error = %err,
                    "failed to enumerate partial-cache files during cleanup"
                );
                success = false;
                break;
            }
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if (name == format!("{hash}.json")
            || name.starts_with(&format!("{hash}.body"))
            || name.starts_with(&format!("{hash}.range."))
            || name.starts_with(&format!("{hash}.meta.")))
            && let Err(err) = tokio::fs::remove_file(entry.path()).await
            && err.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(
                cache_key,
                root = %root.display(),
                error = %err,
                "failed to remove partial-cache file"
            );
            success = false;
        }
    }
    success
}

async fn collect_matching_root_keys<F>(roots: &[PathBuf], mut matches: F) -> HashSet<String>
where
    F: FnMut(&PartialMeta) -> bool,
{
    let mut root_keys = HashSet::new();
    for root in roots {
        let partial_root = root.join("_partial");
        let Ok(mut first_level) = tokio::fs::read_dir(&partial_root).await else {
            continue;
        };
        while let Ok(Some(first_entry)) = first_level.next_entry().await {
            let Ok(file_type) = first_entry.file_type().await else {
                continue;
            };
            if !file_type.is_dir() {
                continue;
            }
            let Ok(mut second_level) = tokio::fs::read_dir(first_entry.path()).await else {
                continue;
            };
            while let Ok(Some(second_entry)) = second_level.next_entry().await {
                let Ok(file_type) = second_entry.file_type().await else {
                    continue;
                };
                if !file_type.is_dir() {
                    continue;
                }
                let Ok(mut files) = tokio::fs::read_dir(second_entry.path()).await else {
                    continue;
                };
                while let Ok(Some(file_entry)) = files.next_entry().await {
                    let path = file_entry.path();
                    if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                        continue;
                    }
                    let Ok(data) = tokio::fs::read(&path).await else {
                        continue;
                    };
                    let Ok(meta) = serde_json::from_slice::<PartialMeta>(&data) else {
                        continue;
                    };
                    if matches(&meta) && !meta.root_key.is_empty() {
                        root_keys.insert(meta.root_key);
                    }
                }
            }
        }
    }
    root_keys
}

fn select_requested_range(meta: &PartialMeta, requested: RequestedRange) -> Option<(u64, u64)> {
    let (start, end) = if let Some(suffix_len) = requested.suffix_len {
        let total = meta.total_size?;
        if suffix_len >= total {
            (0, total.saturating_sub(1))
        } else {
            (total - suffix_len, total.saturating_sub(1))
        }
    } else {
        let start = requested.start?;
        let requested_end = requested
            .end
            .or_else(|| meta.total_size.map(|total| total.saturating_sub(1)))?;
        let end = meta
            .total_size
            .map(|total| requested_end.min(total.saturating_sub(1)))
            .unwrap_or(requested_end);
        (start, end)
    };
    if end < start {
        return None;
    }
    meta.ranges
        .iter()
        .any(|range| range.start <= start && range.end >= end)
        .then_some((start, end))
}

fn normalize_ranges(ranges: &mut Vec<StoredRange>) {
    ranges.retain(|range| range.end >= range.start);
    ranges.sort_by_key(|range| range.start);
    let mut merged: Vec<StoredRange> = Vec::with_capacity(ranges.len());
    for range in ranges.drain(..) {
        if let Some(last) = merged.last_mut()
            && range.start <= last.end.saturating_add(1)
        {
            last.end = last.end.max(range.end);
            continue;
        }
        merged.push(range);
    }
    *ranges = merged;
}

fn required_body_len(meta: &PartialMeta) -> u64 {
    meta.ranges
        .iter()
        .filter_map(|range| range.end.checked_add(1))
        .max()
        .unwrap_or(0)
}

fn partial_hash(cache_key: &str) -> String {
    format!("{:x}", md5_legacy::compute(cache_key.as_bytes()))
}

fn partial_dir_in_root(cache_key: &str, root: &Path) -> PathBuf {
    let hash = partial_hash(cache_key);
    let first = hash.get(0..2).unwrap_or("00");
    let second = hash.get(2..4).unwrap_or("00");
    root.join("_partial").join(first).join(second)
}

fn body_path_in_root(cache_key: &str, root: &Path, generation: u64) -> PathBuf {
    let suffix = if generation == 0 {
        "body".to_string()
    } else {
        format!("body.{generation}")
    };
    partial_path_in_root(cache_key, root, &suffix)
}

fn meta_path_in_root(cache_key: &str, root: &Path) -> PathBuf {
    partial_path_in_root(cache_key, root, "json")
}

fn partial_temp_path(cache_key: &str, root: &Path, kind: &str) -> PathBuf {
    let id = PARTIAL_TEMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    partial_path_in_root(
        cache_key,
        root,
        &format!(
            "{kind}.tmp.{}.{}.{}",
            std::process::id(),
            id,
            uuid::Uuid::new_v4()
        ),
    )
}

fn partial_path_in_root(cache_key: &str, root: &Path, suffix: &str) -> PathBuf {
    let hash = partial_hash(cache_key);
    let first = hash.get(0..2).unwrap_or("00");
    let second = hash.get(2..4).unwrap_or("00");
    root.join("_partial")
        .join(first)
        .join(second)
        .join(format!("{}.{}", hash, suffix))
}

fn system_time_from_timestamp(timestamp: i64) -> std::time::SystemTime {
    if timestamp <= 0 {
        return std::time::UNIX_EPOCH;
    }
    std::time::UNIX_EPOCH
        .checked_add(std::time::Duration::from_secs(timestamp as u64))
        .unwrap_or(std::time::UNIX_EPOCH)
}

fn partial_root_key(cache_key: &str) -> Cow<'_, str> {
    split_partial_cache_key(cache_key)
        .map(|(root, _)| Cow::Owned(root))
        .unwrap_or_else(|| Cow::Borrowed(cache_key))
}

pub fn partial_base_key(cache_key: &str) -> Option<String> {
    split_partial_cache_key(cache_key).map(|(root, _)| root)
}

fn split_partial_cache_key(cache_key: &str) -> Option<(String, Option<String>)> {
    let encoded = cache_key.strip_prefix(PARTIAL_KEY_PREFIX)?;
    let (root_encoded, selector) = encoded.split_once(':')?;
    let root = String::from_utf8(URL_SAFE_NO_PAD.decode(root_encoded.as_bytes()).ok()?).ok()?;
    if selector == "force" {
        return Some((root, None));
    }
    let decoded = URL_SAFE_NO_PAD.decode(selector.as_bytes()).ok()?;
    let range_header = String::from_utf8(decoded).ok()?;
    parse_single_range_header(&range_header)?;
    Some((root, Some(range_header)))
}

struct PartialFileHitHandler {
    file: Option<tokio::fs::File>,
    remaining: u64,
    buf_size: usize,
    cache_key: String,
    roots: Vec<PathBuf>,
    invalidated: bool,
    _purge_guard: tokio::sync::OwnedRwLockReadGuard<()>,
    _root_guard: OwnedMutexGuard<()>,
    _process_lock: Option<crate::cache_hybrid::CacheProcessLockGuard>,
}

impl PartialFileHitHandler {
    async fn invalidate_corrupt_cache(&mut self) {
        if self.invalidated {
            return;
        }
        self.invalidated = true;
        // This handler already owns the purge/read, canonical-key, and
        // cross-process locks. Calling `purge`/`remove` here would try to
        // acquire the same lock again and can deadlock. Remove directly
        // while the existing guards still exclude a concurrent fill/purge.
        self.file.take();
        remove_locked(&self.cache_key, &self.roots).await;
    }
}

#[async_trait::async_trait]
impl pingora_cache::storage::HandleHit for PartialFileHitHandler {
    async fn read_body(&mut self) -> pingora_core::Result<Option<Bytes>> {
        if self.remaining == 0 {
            return Ok(None);
        }
        let read_size = self.remaining.min(self.buf_size as u64) as usize;
        let mut buf = vec![0u8; read_size];
        let read = match self.file.as_mut() {
            Some(file) => match file.read(&mut buf).await {
                Ok(read) => read,
                Err(_) => {
                    self.invalidate_corrupt_cache().await;
                    return Err(pingora_core::Error::new(
                        pingora_core::ErrorType::InternalError,
                    ));
                }
            },
            None => {
                self.invalidate_corrupt_cache().await;
                return Err(pingora_core::Error::new(
                    pingora_core::ErrorType::InternalError,
                ));
            }
        };
        if read == 0 {
            // The response header already advertised the selected range
            // length. Treat an early EOF as corruption instead of returning a
            // successful but truncated 206 response to the client.
            self.invalidate_corrupt_cache().await;
            return Err(pingora_core::Error::new(
                pingora_core::ErrorType::InternalError,
            ));
        }
        buf.truncate(read);
        self.remaining = self.remaining.saturating_sub(read as u64);
        Ok(Some(Bytes::from(buf)))
    }

    async fn finish(
        self: Box<Self>,
        _storage: &'static (dyn pingora_cache::storage::Storage + Sync),
        _key: &pingora_cache::CacheKey,
        _trace: &pingora_cache::trace::SpanHandle,
    ) -> pingora_core::Result<()> {
        Ok(())
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }

    fn as_any_mut(&mut self) -> &mut (dyn std::any::Any + Send + Sync) {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderMap, HeaderValue};
    use pingora_cache::storage::HandleHit;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_base_key(label: &str) -> String {
        let sequence = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        format!(
            "https://partial-cache-test.invalid/{label}-{}-{sequence}",
            std::process::id()
        )
    }

    async fn test_root(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "cloud-node-rust-partial-test-{label}-{}-{}",
            std::process::id(),
            TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        tokio::fs::create_dir_all(&root)
            .await
            .expect("create partial test root");
        root
    }

    fn test_capture(
        start: u64,
        end: u64,
        total: u64,
        etag: Option<&str>,
        last_modified: Option<&str>,
    ) -> PartialCapture {
        PartialCapture {
            start,
            end,
            total: Some(total),
            expires: crate::utils::time::now_timestamp() + 60,
            headers: vec![(
                "content-type".to_string(),
                "application/octet-stream".to_string(),
            )],
            etag: etag.map(str::to_string),
            last_modified: last_modified.map(str::to_string),
            created_at: crate::utils::time::now_timestamp(),
            min_size: None,
            max_size: None,
        }
    }

    async fn read_hit(mut hit: PartialHit) -> Vec<u8> {
        let mut body = Vec::new();
        while let Some(chunk) = hit.handler.read_body().await.expect("read partial hit") {
            body.extend_from_slice(&chunk);
        }
        body
    }

    async fn cleanup(base_key: &str, root: &Path) {
        remove(base_key, &[root.to_path_buf()]).await;
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[test]
    fn response_headers_to_store_excludes_set_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert("set-cookie", HeaderValue::from_static("sid=1"));
        headers.insert("content-type", HeaderValue::from_static("text/html"));
        headers.insert("content-length", HeaderValue::from_static("42"));

        let stored = response_headers_to_store(&headers);

        assert!(
            stored
                .iter()
                .any(|(name, value)| { name == "content-type" && value == "text/html" })
        );
        assert!(!stored.iter().any(|(name, _)| name == "set-cookie"));
        assert!(!stored.iter().any(|(name, _)| name == "content-length"));
    }

    #[test]
    fn content_range_must_match_requested_range_after_origin_clipping() {
        let base = test_base_key("content-range-match");

        let explicit = partial_cache_key(&base, Some("bytes=0-99")).expect("explicit key");
        assert!(content_range_matches_cache_key(
            &explicit,
            &ContentRange {
                start: 0,
                end: 99,
                total: Some(100),
            }
        ));
        assert!(content_range_matches_cache_key(
            &explicit,
            &ContentRange {
                start: 0,
                end: 49,
                total: Some(50),
            }
        ));
        assert!(!content_range_matches_cache_key(
            &explicit,
            &ContentRange {
                start: 0,
                end: 98,
                total: Some(100),
            }
        ));

        let open = partial_cache_key(&base, Some("bytes=90-")).expect("open key");
        assert!(content_range_matches_cache_key(
            &open,
            &ContentRange {
                start: 90,
                end: 99,
                total: Some(100),
            }
        ));

        let suffix = partial_cache_key(&base, Some("bytes=-10")).expect("suffix key");
        assert!(content_range_matches_cache_key(
            &suffix,
            &ContentRange {
                start: 90,
                end: 99,
                total: Some(100),
            }
        ));
        assert!(!content_range_matches_cache_key(
            &suffix,
            &ContentRange {
                start: 80,
                end: 99,
                total: Some(100),
            }
        ));
    }

    #[test]
    fn duplicate_content_ranges_must_be_identical() {
        let mut headers = HeaderMap::new();
        headers.append("content-range", HeaderValue::from_static("bytes 0-9/100"));
        headers.append("content-range", HeaderValue::from_static("bytes 0-9/100"));
        assert_eq!(
            content_range_from_headers(&headers),
            Some(ContentRange {
                start: 0,
                end: 9,
                total: Some(100),
            })
        );

        headers.append("content-range", HeaderValue::from_static("bytes 0-10/100"));
        assert!(content_range_from_headers(&headers).is_none());
    }

    #[tokio::test]
    async fn ranges_with_same_etag_are_merged_without_mixing_bytes() {
        let base = test_base_key("same-etag");
        let root = test_root("same-etag").await;
        let roots = vec![root.clone()];
        let first_key = partial_cache_key(&base, Some("bytes=0-3")).expect("first key");
        let second_key = partial_cache_key(&base, Some("bytes=4-7")).expect("second key");

        assert!(
            store(
                &first_key,
                &test_capture(0, 3, MIN_FORCE_PARTIAL_HIT_BYTES, Some("v1"), None),
                b"ABCD",
                &roots,
                root.clone(),
            )
            .await
            .expect("store first range")
        );
        assert!(
            store(
                &second_key,
                &test_capture(4, 7, MIN_FORCE_PARTIAL_HIT_BYTES, Some("v1"), None),
                b"EFGH",
                &roots,
                root.clone(),
            )
            .await
            .expect("store second range")
        );

        let combined_key = partial_cache_key(&base, Some("bytes=0-7")).expect("combined key");
        let hit = lookup(&combined_key, &roots)
            .await
            .expect("lookup combined range")
            .expect("combined range should hit");
        assert_eq!(read_hit(hit).await, b"ABCDEFGH");

        cleanup(&base, &root).await;
    }

    #[tokio::test]
    async fn ranges_without_a_reliable_validator_are_not_merged() {
        let base = test_base_key("no-validator");
        let root = test_root("no-validator").await;
        let roots = vec![root.clone()];
        let first_key = partial_cache_key(&base, Some("bytes=0-3")).expect("first key");
        let second_key = partial_cache_key(&base, Some("bytes=4-7")).expect("second key");

        assert!(
            store(
                &first_key,
                &test_capture(0, 3, MIN_FORCE_PARTIAL_HIT_BYTES, None, None),
                b"ABCD",
                &roots,
                root.clone(),
            )
            .await
            .expect("store first range")
        );
        assert!(
            store(
                &second_key,
                &test_capture(4, 7, MIN_FORCE_PARTIAL_HIT_BYTES, None, None),
                b"EFGH",
                &roots,
                root.clone(),
            )
            .await
            .expect("store second range")
        );

        let old_range = partial_cache_key(&base, Some("bytes=0-3")).expect("old key");
        assert!(
            lookup(&old_range, &roots)
                .await
                .expect("lookup old range")
                .is_none()
        );
        let new_range = partial_cache_key(&base, Some("bytes=4-7")).expect("new key");
        let hit = lookup(&new_range, &roots)
            .await
            .expect("lookup new range")
            .expect("new range should hit");
        assert_eq!(read_hit(hit).await, b"EFGH");

        cleanup(&base, &root).await;
    }

    #[tokio::test]
    async fn validator_change_invalidates_old_body_version() {
        let base = test_base_key("etag-change");
        let root = test_root("etag-change").await;
        let roots = vec![root.clone()];
        let first_key = partial_cache_key(&base, Some("bytes=0-3")).expect("first key");
        let second_key = partial_cache_key(&base, Some("bytes=4-7")).expect("second key");

        assert!(
            store(
                &first_key,
                &test_capture(0, 3, MIN_FORCE_PARTIAL_HIT_BYTES, Some("v1"), None),
                b"OLD!",
                &roots,
                root.clone(),
            )
            .await
            .expect("store v1")
        );
        assert!(
            store(
                &second_key,
                &test_capture(4, 7, MIN_FORCE_PARTIAL_HIT_BYTES, Some("v2"), None),
                b"NEW!",
                &roots,
                root.clone(),
            )
            .await
            .expect("store v2")
        );

        assert!(
            lookup(&first_key, &roots)
                .await
                .expect("lookup old validator range")
                .is_none()
        );
        let hit = lookup(&second_key, &roots)
            .await
            .expect("lookup new validator range")
            .expect("new validator range should hit");
        assert_eq!(read_hit(hit).await, b"NEW!");

        cleanup(&base, &root).await;
    }

    #[tokio::test]
    async fn mismatched_root_manifest_does_not_hide_valid_later_root() {
        let base = test_base_key("root-selection");
        let bad_root = test_root("root-selection-bad").await;
        let good_root = test_root("root-selection-good").await;
        let good_roots = vec![good_root.clone()];
        let key = partial_cache_key(&base, Some("bytes=0-3")).expect("range key");
        assert!(
            store(
                &key,
                &test_capture(0, 3, MIN_FORCE_PARTIAL_HIT_BYTES, Some("v1"), None),
                b"GOOD",
                &good_roots,
                good_root.clone(),
            )
            .await
            .expect("store good root")
        );

        let root_key = partial_root_key(&key).into_owned();
        let bad_meta = PartialMeta {
            root_key: root_key.clone(),
            root_path: Some(good_root.to_string_lossy().into_owned()),
            total_size: Some(MIN_FORCE_PARTIAL_HIT_BYTES),
            expires: crate::utils::time::now_timestamp() + 60,
            headers: Vec::new(),
            ranges: vec![StoredRange { start: 0, end: 3 }],
            etag: Some("bad".to_string()),
            last_modified: None,
            created_at: crate::utils::time::now_timestamp(),
            body_generation: 1,
        };
        let bad_dir = partial_dir_in_root(&root_key, &bad_root);
        tokio::fs::create_dir_all(&bad_dir)
            .await
            .expect("create bad metadata directory");
        tokio::fs::write(
            meta_path_in_root(&root_key, &bad_root),
            serde_json::to_vec(&bad_meta).expect("serialize bad metadata"),
        )
        .await
        .expect("write bad metadata");

        let roots = vec![bad_root.clone(), good_root.clone()];
        let hit = lookup(&key, &roots)
            .await
            .expect("lookup roots")
            .expect("valid later root should be selected");
        assert_eq!(read_hit(hit).await, b"GOOD");

        cleanup(&base, &bad_root).await;
        cleanup(&base, &good_root).await;
    }

    #[tokio::test]
    async fn truncated_or_missing_old_root_does_not_hide_valid_later_root() {
        let base = test_base_key("missing-body-root");
        let old_root = test_root("missing-body-root-old").await;
        let good_root = test_root("missing-body-root-good").await;
        let key = partial_cache_key(&base, Some("bytes=0-3")).expect("range key");
        let good_roots = vec![good_root.clone()];
        assert!(
            store(
                &key,
                &test_capture(0, 3, MIN_FORCE_PARTIAL_HIT_BYTES, Some("v2"), None),
                b"GOOD",
                &good_roots,
                good_root.clone(),
            )
            .await
            .expect("store good root")
        );

        let root_key = partial_root_key(&key).into_owned();
        let old_dir = partial_dir_in_root(&root_key, &old_root);
        tokio::fs::create_dir_all(&old_dir)
            .await
            .expect("create old metadata directory");
        let old_meta = PartialMeta {
            root_key: root_key.clone(),
            root_path: Some(old_root.to_string_lossy().into_owned()),
            total_size: Some(MIN_FORCE_PARTIAL_HIT_BYTES),
            expires: crate::utils::time::now_timestamp() + 60,
            headers: vec![(
                "content-type".to_string(),
                "application/octet-stream".to_string(),
            )],
            ranges: vec![StoredRange { start: 0, end: 3 }],
            etag: Some("v1".to_string()),
            last_modified: None,
            created_at: crate::utils::time::now_timestamp(),
            body_generation: 1,
        };
        tokio::fs::write(
            meta_path_in_root(&root_key, &old_root),
            serde_json::to_vec(&old_meta).expect("serialize old metadata"),
        )
        .await
        .expect("write old metadata without body");

        let roots = vec![old_root.clone(), good_root.clone()];
        let hit = lookup(&key, &roots)
            .await
            .expect("lookup roots")
            .expect("valid later root should be selected");
        assert_eq!(read_hit(hit).await, b"GOOD");

        cleanup(&base, &old_root).await;
        cleanup(&base, &good_root).await;
    }

    #[tokio::test]
    async fn reader_holds_root_lock_until_body_is_consumed() {
        let base = test_base_key("reader-lock");
        let root = test_root("reader-lock").await;
        let roots = vec![root.clone()];
        let first_key = partial_cache_key(&base, Some("bytes=0-3")).expect("first key");
        let second_key = partial_cache_key(&base, Some("bytes=4-7")).expect("second key");
        let capture = test_capture(0, 3, MIN_FORCE_PARTIAL_HIT_BYTES, Some("v1"), None);
        assert!(
            store(&first_key, &capture, b"ABCD", &roots, root.clone())
                .await
                .expect("store initial range")
        );

        let hit = lookup(&first_key, &roots)
            .await
            .expect("lookup initial range")
            .expect("initial range hit");
        let writer_roots = roots.clone();
        let writer_root = root.clone();
        let writer_key = second_key.clone();
        let mut writer = tokio::spawn(async move {
            store(
                &writer_key,
                &test_capture(4, 7, MIN_FORCE_PARTIAL_HIT_BYTES, Some("v1"), None),
                b"EFGH",
                &writer_roots,
                writer_root,
            )
            .await
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut writer,)
                .await
                .is_err()
        );

        assert_eq!(read_hit(hit).await, b"ABCD");

        // The timeout borrowed the JoinHandle but did not cancel the task; the
        // writer must finish once the hit releases its root-key guard.
        assert!(
            writer
                .await
                .expect("range writer task")
                .expect("range writer result")
        );
        let combined = partial_cache_key(&base, Some("bytes=0-7")).expect("combined key");
        let hit = lookup(&combined, &roots).await.expect("lookup combined");
        assert!(hit.is_some());
        drop(hit);

        cleanup(&base, &root).await;
    }

    #[tokio::test]
    async fn purge_waits_for_active_partial_writer_and_removes_commit() {
        let base = test_base_key("purge-waits-writer");
        let root = test_root("purge-waits-writer").await;
        let roots = vec![root.clone()];
        let key = partial_cache_key(&base, Some("bytes=0-3")).expect("range key");
        let capture = test_capture(0, 3, MIN_FORCE_PARTIAL_HIT_BYTES, Some("v1"), None);

        let mut writer = open_writer(&key, capture, &roots, root.clone())
            .await
            .expect("open writer")
            .expect("writer should be admitted");
        assert!(writer.write(b"ABCD").await.expect("write range"));

        let purge_roots = roots.clone();
        let purge_base = base.clone();
        let mut purge_task = tokio::spawn(async move {
            purge(&purge_base, &purge_roots).await;
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut purge_task)
                .await
                .is_err(),
            "purge must wait for the active range writer"
        );

        assert!(
            writer
                .finish(&roots, root.clone())
                .await
                .expect("finish range writer")
        );
        purge_task.await.expect("purge task");

        assert!(
            lookup(&key, &roots)
                .await
                .expect("lookup purged range")
                .is_none()
        );
        cleanup(&base, &root).await;
    }

    #[tokio::test]
    async fn stale_partial_writer_cannot_publish_after_purge_generation_changes() {
        let base = test_base_key("stale-writer-generation");
        let root = test_root("stale-writer-generation").await;
        let roots = vec![root.clone()];
        let key = partial_cache_key(&base, Some("bytes=0-3")).expect("range key");
        let mut writer = open_writer(
            &key,
            test_capture(0, 3, MIN_FORCE_PARTIAL_HIT_BYTES, Some("v1"), None),
            &roots,
            root.clone(),
        )
        .await
        .expect("open writer")
        .expect("writer should be admitted");
        let temp_path = writer.temp_path.clone();
        assert!(writer.write(b"ABCD").await.expect("write range"));

        // A real purge advances this token after taking the same root lock.
        // Advancing it directly here lets the test exercise the writer's
        // final publication fence without deadlocking against its own lock.
        crate::cache_hybrid::advance_cache_purge_generation();
        assert!(
            !writer
                .finish(&roots, root.clone())
                .await
                .expect("stale writer finish")
        );

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!temp_path.exists());
        assert!(
            lookup(&key, &roots)
                .await
                .expect("lookup stale range")
                .is_none()
        );
        cleanup(&base, &root).await;
    }

    #[tokio::test]
    async fn canonical_full_cache_lock_blocks_partial_writer() {
        let base = test_base_key("canonical-lock");
        let root = test_root("canonical-lock").await;
        let roots = vec![root.clone()];
        let key = partial_cache_key(&base, Some("bytes=0-3")).expect("range key");
        let full_guard = crate::cache_hybrid::cache_write_lock_for_key(&base)
            .lock_owned()
            .await;
        let writer_roots = roots.clone();
        let writer_root = root.clone();
        let writer_key = key.clone();
        let mut writer_task = tokio::spawn(async move {
            open_writer(
                &writer_key,
                test_capture(0, 3, MIN_FORCE_PARTIAL_HIT_BYTES, Some("v1"), None),
                &writer_roots,
                writer_root,
            )
            .await
        });

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut writer_task)
                .await
                .is_err(),
            "partial writer must share the full-object lock"
        );
        drop(full_guard);
        let writer = writer_task
            .await
            .expect("partial writer task")
            .expect("open writer result")
            .expect("writer should be admitted");
        drop(writer);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        cleanup(&base, &root).await;
    }

    #[tokio::test]
    async fn dropped_writer_cleans_range_temp_file() {
        let base = test_base_key("writer-drop");
        let root = test_root("writer-drop").await;
        let roots = vec![root.clone()];
        let key = partial_cache_key(&base, Some("bytes=0-3")).expect("range key");
        let mut writer = open_writer(
            &key,
            test_capture(0, 3, MIN_FORCE_PARTIAL_HIT_BYTES, Some("v1"), None),
            &roots,
            root.clone(),
        )
        .await
        .expect("open writer")
        .expect("writer should be admitted");
        let temp_path = writer.temp_path.clone();
        assert!(!writer.write(b"too-long").await.expect("overflow write"));
        drop(writer);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!temp_path.exists());

        cleanup(&base, &root).await;
    }

    #[tokio::test]
    async fn partial_hit_early_eof_is_an_error() {
        let base = test_base_key("partial-early-eof");
        let root = test_root("partial-early-eof").await;
        let path = body_path_in_root(&base, &root, 0);
        tokio::fs::create_dir_all(path.parent().expect("body parent"))
            .await
            .expect("create body parent");
        tokio::fs::write(&path, b"AB")
            .await
            .expect("write short body");
        let metadata_path = meta_path_in_root(&base, &root);
        tokio::fs::write(&metadata_path, b"corrupt")
            .await
            .expect("write corrupt metadata marker");
        let file = tokio::fs::File::open(&path).await.expect("open short body");
        let purge_guard = crate::cache_hybrid::acquire_cache_purge_read_guard().await;
        let root_guard = lock_for(&base).lock_owned().await;
        let mut handler = PartialFileHitHandler {
            file: Some(file),
            remaining: 4,
            buf_size: 128,
            cache_key: base.clone(),
            roots: vec![root.clone()],
            invalidated: false,
            _purge_guard: purge_guard,
            _root_guard: root_guard,
            _process_lock: None,
        };

        assert_eq!(
            handler
                .read_body()
                .await
                .expect("read short body")
                .expect("first chunk")
                .as_ref(),
            b"AB"
        );
        assert!(handler.read_body().await.is_err());
        assert!(!path.exists(), "corrupt partial body must be removed");
        assert!(
            !metadata_path.exists(),
            "metadata paired with corrupt partial body must be removed"
        );

        drop(handler);
        cleanup(&base, &root).await;
    }

    #[tokio::test]
    async fn metadata_publish_failure_removes_new_body_and_temps() {
        let base = test_base_key("meta-rename-failure");
        let root = test_root("meta-rename-failure").await;
        let roots = vec![root.clone()];
        let key = partial_cache_key(&base, Some("bytes=0-3")).expect("range key");
        let root_key = partial_root_key(&key).into_owned();
        let meta_path = meta_path_in_root(&root_key, &root);
        if let Some(parent) = meta_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .expect("create metadata parent");
        }
        tokio::fs::create_dir(&meta_path)
            .await
            .expect("create metadata directory");

        let result = store(
            &key,
            &test_capture(0, 3, MIN_FORCE_PARTIAL_HIT_BYTES, Some("v1"), None),
            b"FAIL",
            &roots,
            root.clone(),
        )
        .await;
        assert!(result.is_err());
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let dir = partial_dir_in_root(&root_key, &root);
        let mut entries = tokio::fs::read_dir(&dir).await.expect("read partial dir");
        while let Some(entry) = entries.next_entry().await.expect("read directory entry") {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            assert!(!name.starts_with(&format!("{}.body.", partial_hash(&root_key))));
            assert!(!name.starts_with(&format!("{}.range.", partial_hash(&root_key))));
            assert!(!name.starts_with(&format!("{}.meta.", partial_hash(&root_key))));
        }

        cleanup(&base, &root).await;
    }

    #[tokio::test]
    async fn expired_and_out_of_bounds_ranges_are_misses() {
        let base = test_base_key("invalid-range");
        let root = test_root("invalid-range").await;
        let roots = vec![root.clone()];
        let key = partial_cache_key(&base, Some("bytes=0-3")).expect("range key");
        let root_key = partial_root_key(&key).into_owned();
        let metadata = PartialMeta {
            root_key: root_key.clone(),
            root_path: Some(root.to_string_lossy().into_owned()),
            total_size: Some(MIN_FORCE_PARTIAL_HIT_BYTES),
            expires: crate::utils::time::now_timestamp() - 1,
            headers: Vec::new(),
            ranges: vec![StoredRange { start: 0, end: 3 }],
            etag: Some("v1".to_string()),
            last_modified: None,
            created_at: crate::utils::time::now_timestamp() - 10,
            body_generation: 1,
        };
        let dir = partial_dir_in_root(&root_key, &root);
        tokio::fs::create_dir_all(&dir)
            .await
            .expect("create partial dir");
        tokio::fs::write(
            meta_path_in_root(&root_key, &root),
            serde_json::to_vec(&metadata).expect("serialize metadata"),
        )
        .await
        .expect("write metadata");
        tokio::fs::write(body_path_in_root(&root_key, &root, 1), b"BODY")
            .await
            .expect("write body");

        assert!(
            lookup(&key, &roots)
                .await
                .expect("expired lookup")
                .is_none()
        );
        assert!(!meta_path_in_root(&root_key, &root).exists());

        let active_key = partial_cache_key(&base, Some("bytes=0-3")).expect("active key");
        let active_capture = test_capture(0, 3, MIN_FORCE_PARTIAL_HIT_BYTES, Some("v1"), None);
        assert!(
            store(&active_key, &active_capture, b"BODY", &roots, root.clone(),)
                .await
                .expect("store active range")
        );
        let out_of_bounds =
            partial_cache_key(&base, Some("bytes=262140-262150")).expect("out of bounds key");
        assert!(
            lookup(&out_of_bounds, &roots)
                .await
                .expect("out of bounds lookup")
                .is_none()
        );

        cleanup(&base, &root).await;
    }
}
