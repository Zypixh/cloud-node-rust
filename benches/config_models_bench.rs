use criterion::{black_box, criterion_group, criterion_main, Criterion};
use cloud_node_rust::config_models::{
    parse_life_to_seconds, URLPattern, SizeCapacity, ServerConfig,
};
use serde_json::Value;

fn bench_parse_life_to_seconds(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse_life_to_seconds");

    group.bench_function("seconds_unit", |b| {
        let v = Value::String("30s".to_string());
        b.iter(|| parse_life_to_seconds(black_box(&v)))
    });

    group.bench_function("minutes_unit", |b| {
        let v = Value::String("5m".to_string());
        b.iter(|| parse_life_to_seconds(black_box(&v)))
    });

    group.bench_function("hours_unit", |b| {
        let v = Value::String("2h".to_string());
        b.iter(|| parse_life_to_seconds(black_box(&v)))
    });

    group.bench_function("days_unit", |b| {
        let v = Value::String("7d".to_string());
        b.iter(|| parse_life_to_seconds(black_box(&v)))
    });

    group.bench_function("number_value", |b| {
        let v = Value::Number(3600.into());
        b.iter(|| parse_life_to_seconds(black_box(&v)))
    });

    group.finish();
}

fn bench_url_pattern(c: &mut Criterion) {
    let mut group = c.benchmark_group("url_pattern_matches");

    // Regex pattern
    let regex_pattern = URLPattern {
        type_name: "regex".to_string(),
        pattern: r"^/api/v\d+/users/\d+/profile$".to_string(),
        ..Default::default()
    };

    group.bench_function("regex_hit", |b| {
        b.iter(|| regex_pattern.matches(black_box("/api/v2/users/12345/profile")))
    });

    group.bench_function("regex_miss", |b| {
        b.iter(|| regex_pattern.matches(black_box("/api/v2/users/abc/profile")))
    });

    // Wildcard pattern
    let wildcard_pattern = URLPattern {
        type_name: "wildcard".to_string(),
        pattern: "/api/v1/users/*/profile".to_string(),
        ..Default::default()
    };

    group.bench_function("wildcard_hit", |b| {
        b.iter(|| wildcard_pattern.matches(black_box("/api/v1/users/123/profile")))
    });

    group.bench_function("wildcard_miss", |b| {
        b.iter(|| wildcard_pattern.matches(black_box("/api/v2/admin/delete")))
    });

    // Images extension
    let image_pattern = URLPattern {
        type_name: "images".to_string(),
        ..Default::default()
    };

    group.bench_function("image_extension_hit", |b| {
        b.iter(|| image_pattern.matches(black_box("/static/photo.jpg")))
    });

    // Audios extension
    let audio_pattern = URLPattern {
        type_name: "audios".to_string(),
        ..Default::default()
    };

    group.bench_function("audio_extension_miss", |b| {
        b.iter(|| audio_pattern.matches(black_box("/static/file.txt")))
    });

    // Videos extension
    let video_pattern = URLPattern {
        type_name: "videos".to_string(),
        ..Default::default()
    };

    group.bench_function("video_extension_hit", |b| {
        b.iter(|| video_pattern.matches(black_box("/media/clip.mp4")))
    });

    group.finish();
}

fn bench_size_capacity(c: &mut Criterion) {
    let mut group = c.benchmark_group("size_capacity");

    let json_kb = Value::Object({
        let mut m = serde_json::Map::new();
        m.insert("count".to_string(), Value::Number(1024.into()));
        m.insert("unit".to_string(), Value::String("kb".to_string()));
        m
    });

    group.bench_function("from_json_kb", |b| {
        b.iter(|| SizeCapacity::from_json(black_box(&json_kb)))
    });

    group.bench_function("from_json_then_to_bytes", |b| {
        b.iter(|| {
            let sc = SizeCapacity::from_json(black_box(&json_kb));
            black_box(sc.to_bytes())
        })
    });

    let json_mb = Value::Object({
        let mut m = serde_json::Map::new();
        m.insert("count".to_string(), Value::Number(100.into()));
        m.insert("unit".to_string(), Value::String("m".to_string()));
        m
    });

    group.bench_function("from_json_mb_to_bytes", |b| {
        b.iter(|| {
            let sc = SizeCapacity::from_json(black_box(&json_mb));
            black_box(sc.to_bytes())
        })
    });

    group.finish();
}

fn bench_server_config(c: &mut Criterion) {
    let mut server = ServerConfig {
        id: Some(42),
        ..Default::default()
    };
    server.server_names.push(
        cloud_node_rust::config_models::ServerNameConfig {
            name: "www.example.com".to_string(),
            sub_names: vec!["api.example.com".to_string(), "cdn.example.com".to_string()],
            ..Default::default()
        },
    );

    let mut group = c.benchmark_group("server_config");

    group.bench_function("get_plain_server_names", |b| {
        b.iter(|| server.get_plain_server_names())
    });

    group.bench_function("get_first_host", |b| {
        b.iter(|| server.get_first_host())
    });

    group.bench_function("numeric_id", |b| {
        b.iter(|| server.numeric_id())
    });

    group.bench_function("is_sni_passthrough_no", |b| {
        b.iter(|| server.is_sni_passthrough())
    });

    group.bench_function("has_valid_traffic_limit", |b| {
        b.iter(|| server.has_valid_traffic_limit())
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_parse_life_to_seconds,
    bench_url_pattern,
    bench_size_capacity,
    bench_server_config,
);
criterion_main!(benches);
