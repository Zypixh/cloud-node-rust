use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use dashmap::DashSet;
use http::HeaderMap;
use pingora_cache::CacheMeta;
use pingora_cache::storage::HitHandler;
use pingora_http::ResponseHeader;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashSet;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::LazyLock as Lazy;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Mutex;

pub const PARTIAL_KEY_PREFIX: &str = "__cloud_node_partial:";
pub const MIN_FORCE_PARTIAL_HIT_BYTES: u64 = 256 * 1024;
const PARTIAL_LOCK_SHARDS: usize = 256;

#[derive(Clone, Debug)]
pub struct PartialCapture {
    pub start: u64,
    pub end: u64,
    pub total: Option<u64>,
    pub expires: i64,
    pub headers: Vec<(String, String)>,
    pub min_size: Option<i64>,
    pub max_size: Option<i64>,
}

pub struct PartialWriter {
    root_key: String,
    capture: PartialCapture,
    file: tokio::fs::File,
    written: u64,
}

pub struct PartialHit {
    pub meta: CacheMeta,
    pub handler: HitHandler,
}

#[derive(Debug)]
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
    total_size: Option<u64>,
    expires: i64,
    headers: Vec<(String, String)>,
    ranges: Vec<StoredRange>,
}

static PARTIAL_LOCKS: Lazy<Vec<Arc<Mutex<()>>>> = Lazy::new(|| {
    (0..PARTIAL_LOCK_SHARDS)
        .map(|_| Arc::new(Mutex::new(())))
        .collect()
});
static FORCE_HIT_ROOT_KEYS: Lazy<DashSet<String>> = Lazy::new(DashSet::new);

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

pub fn has_force_hit(base_key: &str) -> bool {
    FORCE_HIT_ROOT_KEYS.contains(base_key)
}

fn lock_for(cache_key: &str) -> Arc<Mutex<()>> {
    let mut hasher = DefaultHasher::new();
    cache_key.hash(&mut hasher);
    let idx = (hasher.finish() as usize) % PARTIAL_LOCK_SHARDS;
    PARTIAL_LOCKS[idx].clone()
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
        let suffix_len = end.parse::<u64>().ok().filter(|value| *value > 0)?;
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
    let total = total.trim().parse::<u64>().ok().filter(|total| *total > 0);
    Some(ContentRange { start, end, total })
}

pub fn content_range_from_headers(headers: &HeaderMap) -> Option<ContentRange> {
    headers
        .get("content-range")
        .and_then(|value| value.to_str().ok())
        .and_then(parse_content_range)
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
    let Some(mut meta) = load_meta(root_key, roots).await? else {
        return Ok(None);
    };

    let now = crate::utils::time::now_timestamp();
    if meta.expires <= now {
        remove(root_key, roots).await;
        return Ok(None);
    }

    normalize_ranges(&mut meta.ranges);
    let is_force_lookup = range_header.is_none();
    let selected = if let Some(range_header) = range_header.as_deref() {
        let Some(requested) = parse_single_range_header(range_header) else {
            return Ok(None);
        };
        select_requested_range(&meta, requested)
    } else {
        select_force_range(&meta)
    };

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
    let len = end.saturating_sub(start).saturating_add(1);
    if is_force_lookup && len < MIN_FORCE_PARTIAL_HIT_BYTES {
        return Ok(None);
    }
    let Some(existing_data_path) = find_existing_path(root_key, roots, "body").await? else {
        return Ok(None);
    };
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
    if file_len < start.saturating_add(len) {
        return Ok(None);
    }

    let ttl = (meta.expires - now).max(0) as u64;
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
        std::time::SystemTime::now() + std::time::Duration::from_secs(ttl),
        std::time::SystemTime::now(),
        0,
        0,
        header,
    );
    Ok(Some(PartialHit {
        meta,
        handler: Box::new(PartialFileHitHandler {
            file,
            remaining: len,
            buf_size: 128 * 1024,
        }),
    }))
}

#[allow(unused_variables)]
pub async fn open_writer(
    cache_key: &str,
    capture: PartialCapture,
    roots: &[PathBuf],
    write_root: PathBuf,
) -> std::io::Result<Option<PartialWriter>> {
    let root_key = partial_root_key(cache_key);
    let root_key = root_key.as_ref();
    if !capture_allows_store(&capture, None) {
        return Ok(None);
    }

    let _lock_arc = lock_for(root_key);
    let _guard = _lock_arc.lock().await;
    let data_path = data_path_in_root(root_key, &write_root);
    if let Some(parent) = data_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(&data_path)
        .await?;
    file.seek(std::io::SeekFrom::Start(capture.start)).await?;
    drop(_guard);

    Ok(Some(PartialWriter {
        root_key: root_key.to_string(),
        capture,
        file,
        written: 0,
    }))
}

impl PartialWriter {
    pub async fn write(&mut self, data: &[u8]) -> std::io::Result<bool> {
        if data.is_empty() {
            return Ok(true);
        }
        let expected_len = self.capture.end - self.capture.start + 1;
        if self.written.saturating_add(data.len() as u64) > expected_len {
            return Ok(false);
        }
        self.file.write_all(data).await?;
        self.written += data.len() as u64;
        Ok(true)
    }

    pub async fn finish(mut self, roots: &[PathBuf], write_root: PathBuf) -> std::io::Result<bool> {
        self.file.flush().await?;
        if self.written != self.capture.end - self.capture.start + 1 {
            return Ok(false);
        }
        merge_meta(
            &self.root_key,
            &self.capture,
            roots,
            &write_root,
            Some(self.written),
        )
        .await
    }
}

fn capture_allows_store(capture: &PartialCapture, body_len: Option<u64>) -> bool {
    if capture.end < capture.start {
        return false;
    }
    let expected_len = capture.end - capture.start + 1;
    if body_len.is_some_and(|len| len != expected_len) {
        return false;
    }
    if let Some(total) = capture.total {
        if total < MIN_FORCE_PARTIAL_HIT_BYTES {
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
    let root_key = partial_root_key(cache_key);
    let root_key = root_key.as_ref();
    if !capture_allows_store(capture, Some(body.len() as u64)) {
        return Ok(false);
    }

    let _lock_arc = lock_for(root_key);
    let _guard = _lock_arc.lock().await;
    let data_path = data_path_in_root(root_key, &write_root);
    if let Some(parent) = data_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(&data_path)
        .await?;
    file.seek(std::io::SeekFrom::Start(capture.start)).await?;
    file.write_all(body).await?;
    file.flush().await?;

    merge_meta_locked(root_key, capture, roots, &write_root).await
}

async fn merge_meta(
    root_key: &str,
    capture: &PartialCapture,
    roots: &[PathBuf],
    write_root: &PathBuf,
    body_len: Option<u64>,
) -> std::io::Result<bool> {
    if !capture_allows_store(capture, body_len) {
        return Ok(false);
    }
    let _lock_arc = lock_for(root_key);
    let _guard = _lock_arc.lock().await;
    merge_meta_locked(root_key, capture, roots, write_root).await
}

async fn merge_meta_locked(
    root_key: &str,
    capture: &PartialCapture,
    roots: &[PathBuf],
    write_root: &PathBuf,
) -> std::io::Result<bool> {
    let mut meta = load_meta(root_key, roots)
        .await?
        .filter(|meta| {
            meta.expires > crate::utils::time::now_timestamp() && meta.total_size == capture.total
        })
        .unwrap_or(PartialMeta {
            root_key: root_key.to_string(),
            total_size: capture.total,
            expires: capture.expires,
            headers: capture.headers.clone(),
            ranges: Vec::new(),
        });
    meta.root_key = root_key.to_string();
    meta.total_size = capture.total.or(meta.total_size);
    meta.expires = meta.expires.max(capture.expires);
    if !capture.headers.is_empty() {
        meta.headers = capture.headers.clone();
    }
    meta.ranges.push(StoredRange {
        start: capture.start,
        end: capture.end,
    });
    normalize_ranges(&mut meta.ranges);
    if select_force_range(&meta).is_some() {
        FORCE_HIT_ROOT_KEYS.insert(root_key.to_string());
    } else {
        FORCE_HIT_ROOT_KEYS.remove(root_key);
    }

    let meta_path = meta_path_in_root(root_key, write_root);
    if let Some(parent) = meta_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let meta_json = serde_json::to_vec(&meta)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    let temp_path = meta_path.with_extension(format!(
        "json.tmp.{}.{}",
        std::process::id(),
        crate::utils::time::now_timestamp_millis()
    ));
    tokio::fs::write(&temp_path, meta_json).await?;
    tokio::fs::rename(&temp_path, &meta_path).await?;
    Ok(true)
}

pub async fn purge(cache_key: &str, roots: &[PathBuf]) {
    let root_key = partial_root_key(cache_key);
    remove(root_key.as_ref(), roots).await;
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

async fn load_meta(cache_key: &str, roots: &[PathBuf]) -> std::io::Result<Option<PartialMeta>> {
    let Some(path) = find_existing_path(cache_key, roots, "json").await? else {
        return Ok(None);
    };
    let data = match tokio::fs::read(path).await {
        Ok(data) => data,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    let mut meta: PartialMeta = serde_json::from_slice(&data)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    if meta.root_key.is_empty() {
        meta.root_key = cache_key.to_string();
    }
    Ok(Some(meta))
}

async fn remove(cache_key: &str, roots: &[PathBuf]) {
    let _lock_arc = lock_for(cache_key);
    let _guard = _lock_arc.lock().await;
    FORCE_HIT_ROOT_KEYS.remove(cache_key);
    for root in roots {
        let _ = tokio::fs::remove_file(data_path_in_root(cache_key, root)).await;
        let _ = tokio::fs::remove_file(meta_path_in_root(cache_key, root)).await;
    }
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
        let end = requested
            .end
            .or_else(|| meta.total_size.map(|total| total.saturating_sub(1)))?;
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

fn select_force_range(meta: &PartialMeta) -> Option<(u64, u64)> {
    meta.ranges
        .iter()
        .filter(|range| range.end >= range.start)
        .find(|range| range.end - range.start + 1 >= MIN_FORCE_PARTIAL_HIT_BYTES)
        .map(|range| (range.start, range.end))
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

async fn find_existing_path(
    cache_key: &str,
    roots: &[PathBuf],
    suffix: &str,
) -> std::io::Result<Option<PathBuf>> {
    for root in roots {
        let path = partial_path_in_root(cache_key, root, suffix);
        match tokio::fs::metadata(&path).await {
            Ok(_) => return Ok(Some(path)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
    }
    Ok(None)
}

fn data_path_in_root(cache_key: &str, root: &PathBuf) -> PathBuf {
    partial_path_in_root(cache_key, root, "body")
}

fn meta_path_in_root(cache_key: &str, root: &PathBuf) -> PathBuf {
    partial_path_in_root(cache_key, root, "json")
}

fn partial_path_in_root(cache_key: &str, root: &PathBuf, suffix: &str) -> PathBuf {
    let root_key = partial_root_key(cache_key);
    let hash = format!("{:x}", md5_legacy::compute(root_key.as_ref().as_bytes()));
    let first = hash.get(0..2).unwrap_or("00");
    let second = hash.get(2..4).unwrap_or("00");
    root.join("_partial")
        .join(first)
        .join(second)
        .join(format!("{}.{}", hash, suffix))
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
    file: tokio::fs::File,
    remaining: u64,
    buf_size: usize,
}

#[async_trait::async_trait]
impl pingora_cache::storage::HandleHit for PartialFileHitHandler {
    async fn read_body(&mut self) -> pingora_core::Result<Option<Bytes>> {
        if self.remaining == 0 {
            return Ok(None);
        }
        let read_size = self.remaining.min(self.buf_size as u64) as usize;
        let mut buf = vec![0u8; read_size];
        let read = self
            .file
            .read(&mut buf)
            .await
            .map_err(|_| pingora_core::Error::new(pingora_core::ErrorType::InternalError))?;
        if read == 0 {
            self.remaining = 0;
            return Ok(None);
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
    use super::response_headers_to_store;
    use http::{HeaderMap, HeaderValue};

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
}
