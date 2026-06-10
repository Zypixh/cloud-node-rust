use cloud_node_rust::cache_hybrid::{HybridStorage, fast_l1_lookup};
use cloud_node_rust::config_models::{HTTPHTMLOptimizationConfig, SSLCertConfig, SSLPolicyConfig};
use cloud_node_rust::firewall::verifier::WafVerifier;
use cloud_node_rust::metrics::analyzer::analyze_request;
use cloud_node_rust::proxy::EdgeProxy;
use cloud_node_rust::ssl::{DynamicCertSelector, sync_certs};
use criterion::{Criterion, criterion_group, criterion_main};
use image::{DynamicImage, ImageBuffer, ImageFormat, Rgba};
use pingora_cache::{CacheKey, CacheMeta, Storage, trace::Span};
use pingora_http::ResponseHeader;
use serde_json::json;
use std::hint::black_box;
use std::io::Cursor;
use std::net::IpAddr;
use std::time::Duration;
use tokio::runtime::Runtime;

fn cache_meta_with_headers() -> CacheMeta {
    let mut header = ResponseHeader::build(200, None).expect("response header");
    header
        .insert_header("content-type", "text/plain; charset=utf-8")
        .expect("content-type");
    header
        .insert_header("cache-control", "public, max-age=3600")
        .expect("cache-control");
    header.insert_header("etag", "\"bench\"").expect("etag");

    let now = std::time::SystemTime::now();
    CacheMeta::new(now + Duration::from_secs(3600), now, 0, 0, header)
}

fn bench_fast_l1(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let storage: &'static HybridStorage = Box::leak(Box::new(HybridStorage::new(
        10 * 1024 * 1024,
        "target/targeted_fast_l1",
    )));
    let key = CacheKey::new("http", "fast-l1.example", "/asset.txt");
    let key_str = key.primary_key_str().unwrap_or("fast-l1.example");
    let body = bytes::Bytes::from(vec![b'a'; 32 * 1024]);
    let meta = cache_meta_with_headers();

    HybridStorage::bench_fast_l1_remove(key_str);
    assert!(HybridStorage::bench_fast_l1_insert(
        key_str,
        body.clone(),
        &meta,
        3600
    ));

    let mut group = c.benchmark_group("fast_l1");
    group.bench_function("body_lookup_hit_32kb", |b| {
        b.iter(|| {
            let hit = fast_l1_lookup(black_box(key_str));
            black_box(hit)
        })
    });
    group.bench_function("storage_lookup_hit_with_headers_32kb", |b| {
        b.to_async(&rt).iter(|| async {
            let hit = storage
                .lookup(black_box(&key), &Span::inactive().handle())
                .await;
            black_box(hit)
        })
    });
    HybridStorage::bench_compute_memory_budget();
    group.bench_function("memory_budget_cached", |b| {
        b.iter(|| black_box(HybridStorage::bench_compute_memory_budget()))
    });
    group.finish();
}

fn png_fixture() -> Vec<u8> {
    let img = ImageBuffer::from_fn(128, 128, |x, y| {
        let r = ((x * 3 + y) % 255) as u8;
        let g = ((x + y * 5) % 255) as u8;
        let b = ((x * y) % 255) as u8;
        Rgba([r, g, b, 255])
    });
    let mut cursor = Cursor::new(Vec::new());
    DynamicImage::ImageRgba8(img)
        .write_to(&mut cursor, ImageFormat::Png)
        .expect("png fixture");
    cursor.into_inner()
}

fn repeated_html() -> Vec<u8> {
    let mut out = String::with_capacity(80 * 1024);
    for _ in 0..512 {
        out.push_str(
            "<div class=\"item\">\n  <!-- bench comment -->\n  <span>hello     world</span>\n</div>\n",
        );
    }
    out.into_bytes()
}

fn repeated_css() -> Vec<u8> {
    let mut out = String::with_capacity(64 * 1024);
    for _ in 0..1024 {
        out.push_str("/* bench */ .card > .title { color: #123456; margin: 0  10px; }\n");
    }
    out.into_bytes()
}

fn repeated_js() -> Vec<u8> {
    let mut out = String::with_capacity(64 * 1024);
    for _ in 0..1024 {
        out.push_str("// bench\nfunction f(x) { return x + 1; }\n");
    }
    out.into_bytes()
}

fn bench_response_body_cpu(c: &mut Criterion) {
    let png = png_fixture();
    let html = repeated_html();
    let css = repeated_css();
    let js = repeated_js();
    let html_config = HTTPHTMLOptimizationConfig::default();
    let aes_body = vec![b'x'; 1024 * 1024];
    let key = [7u8; 16];
    let iv = [3u8; 16];

    let mut group = c.benchmark_group("response_body_cpu");
    group.sample_size(20);
    group.bench_function("webp_convert_png_128", |b| {
        b.iter(|| {
            let out = EdgeProxy::bench_convert_to_webp("image/png", black_box(&png), black_box(80));
            black_box(out)
        })
    });
    group.bench_function("minify_html_40kb", |b| {
        b.iter(|| {
            let out = EdgeProxy::bench_minify_html(black_box(&html), black_box(&html_config));
            black_box(out)
        })
    });
    group.bench_function("minify_css_64kb", |b| {
        b.iter(|| {
            let out = EdgeProxy::bench_minify_css(black_box(&css));
            black_box(out)
        })
    });
    group.bench_function("minify_js_40kb", |b| {
        b.iter(|| {
            let out = EdgeProxy::bench_minify_js(black_box(&js));
            black_box(out)
        })
    });
    group.bench_function("aes128_cbc_encrypt_1mb", |b| {
        b.iter(|| {
            let out = EdgeProxy::bench_aes128_cbc_encrypt(black_box(&aes_body), key, iv);
            black_box(out)
        })
    });
    group.finish();
}

fn ssl_cert_config() -> SSLCertConfig {
    let cert = include_str!("../pingora-main/pingora-core/examples/keys/server/cert.pem");
    let key = include_str!("../pingora-main/pingora-core/examples/keys/server/key.pem");
    SSLCertConfig {
        id: 1,
        is_on: true,
        cert_data_json: Some(json!(cert)),
        key_data_json: Some(json!(key)),
        dns_names: Vec::new(),
    }
}

fn ssl_policy() -> SSLPolicyConfig {
    SSLPolicyConfig {
        id: 1,
        is_on: true,
        certs: Vec::new(),
        http2_enabled: false,
        min_version: String::new(),
        hsts: None,
    }
}

fn bench_tls_selector(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let selector = DynamicCertSelector::new();
    let certs = vec![ssl_cert_config()];
    let _policy = ssl_policy();
    rt.block_on(sync_certs(&selector, &certs));

    let mut group = c.benchmark_group("tls_selector");
    group.bench_function("lookup_exact", |b| {
        b.iter(|| black_box(selector.bench_find_pair(black_box("openrusty.org"))))
    });
    group.bench_function("lookup_wildcard", |b| {
        b.iter(|| black_box(selector.bench_find_pair(black_box("www.openrusty.org"))))
    });
    group.bench_function("lookup_default", |b| {
        b.iter(|| black_box(selector.bench_find_pair(black_box("missing.example"))))
    });
    group.bench_function("sync_single_cert_reuse", |b| {
        b.to_async(&rt).iter(|| async {
            sync_certs(&selector, black_box(&certs)).await;
        })
    });
    group.finish();
}

fn bench_analyzer_cache(c: &mut Criterion) {
    let ip: IpAddr = "1.1.1.1".parse().unwrap();
    let repeated_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36";
    let _ = analyze_request(ip, repeated_ua);
    let unique_uas: Vec<String> = (0..1024)
        .map(|i| {
            format!(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/123.0.{}.0 Safari/537.36",
                i
            )
        })
        .collect();
    let mut unique_index = 0usize;

    let mut group = c.benchmark_group("analyzer_cache");
    group.bench_function("ua_cache_hit_repeated", |b| {
        b.iter(|| {
            let stats = analyze_request(black_box(ip), black_box(repeated_ua));
            black_box(stats)
        })
    });
    group.bench_function("ua_cache_miss_rotating", |b| {
        b.iter(|| {
            let ua = &unique_uas[unique_index % unique_uas.len()];
            unique_index = unique_index.wrapping_add(1);
            let stats = analyze_request(black_box(ip), black_box(ua.as_str()));
            black_box(stats)
        })
    });
    group.finish();
}

fn bench_waf_verifier(c: &mut Criterion) {
    let secret = "bench-secret-key-0123456789012345";
    let verifier = WafVerifier::new(secret);
    let ip = "203.0.113.10";
    let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36";
    let token = verifier.generate_token(ip, ua);

    let mut group = c.benchmark_group("waf_verifier");
    group.bench_function("construct", |b| {
        b.iter(|| black_box(WafVerifier::new(black_box(secret))))
    });
    group.bench_function("verify_existing_token", |b| {
        b.iter(|| {
            let ok = verifier.verify_token(
                black_box(ip),
                black_box(ua),
                black_box(&token),
                black_box(3600),
            );
            black_box(ok)
        })
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_fast_l1,
    bench_response_body_cpu,
    bench_tls_selector,
    bench_analyzer_cache,
    bench_waf_verifier
);
criterion_main!(benches);
