use criterion::{black_box, criterion_group, criterion_main, Criterion};
use cloud_node_rust::utils::template::format_template;

fn bench_template_simple(c: &mut Criterion) {
    let template = "Hello, ${name}! Your ID is ${id}.";
    let resolver = |var: &str| match var {
        "name" => "Gemini".to_string(),
        "id" => "12345".to_string(),
        _ => "".to_string(),
    };

    c.bench_function("template_simple", |b| {
        b.iter(|| format_template(black_box(template), black_box(resolver)))
    });
}

fn bench_template_complex(c: &mut Criterion) {
    let template = "Original: ${data} | MD5: ${data|md5} | Base64: ${data|base64Encode}";
    let resolver = |var: &str| match var {
        "data" => "some-sensitive-data-to-be-encoded".to_string(),
        _ => "".to_string(),
    };

    c.bench_function("template_complex_pipeline", |b| {
        b.iter(|| format_template(black_box(template), black_box(resolver)))
    });
}

criterion_group!(benches, bench_template_simple, bench_template_complex);
criterion_main!(benches);
