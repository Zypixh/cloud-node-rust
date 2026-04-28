use criterion::{black_box, criterion_group, criterion_main, Criterion};
use cloud_node_rust::firewall::matcher::evaluate_operator;

fn bench_firewall_operators(c: &mut Criterion) {
    let sql_injection_payload = "SELECT * FROM users WHERE id = 1 UNION SELECT password FROM admin--";
    let xss_payload = "<script>alert('xss')</script>";

    let mut group = c.benchmark_group("firewall_matcher");

    group.bench_function("sqli_detect", |b| {
        b.iter(|| {
            evaluate_operator(black_box(sql_injection_payload), "contains sql injection", "", false)
        })
    });

    group.bench_function("xss_detect", |b| {
        b.iter(|| {
            evaluate_operator(black_box(xss_payload), "contains xss", "", false)
        })
    });

    group.bench_function("ip_cidr_match", |b| {
        let ip = "192.168.1.50";
        let cidr_list = "10.0.0.0/8\n172.16.0.0/12\n192.168.1.0/24\n1.1.1.1/32";
        b.iter(|| {
            evaluate_operator(black_box(ip), "in ip list", black_box(cidr_list), false)
        })
    });

    group.bench_function("regex_match", |b| {
        let test_string = "hello world foo bar baz 12345";
        let pattern = r"foo\s+bar\s+\w+\s+\d+";
        b.iter(|| {
            evaluate_operator(black_box(test_string), "match", black_box(pattern), false)
        })
    });

    group.bench_function("regex_not_match", |b| {
        let test_string = "no match here at all folks";
        let pattern = r"foo\s+bar\s+\w+\s+\d+";
        b.iter(|| {
            evaluate_operator(black_box(test_string), "not match", black_box(pattern), false)
        })
    });

    group.bench_function("regex_case_insensitive", |b| {
        let test_string = "HELLO WORLD FOO BAR BAZ 12345";
        let pattern = r"hello\s+world\s+foo\s+\w+\s+\d+";
        b.iter(|| {
            evaluate_operator(black_box(test_string), "match", black_box(pattern), true)
        })
    });

    group.bench_function("wildcard_match", |b| {
        let test_string = "/api/v1/users/123/profile";
        let pattern = "/api/v1/users/*/profile";
        b.iter(|| {
            evaluate_operator(black_box(test_string), "wildcard match", black_box(pattern), false)
        })
    });

    group.bench_function("wildcard_not_match", |b| {
        let test_string = "/api/v1/admin/delete";
        let pattern = "/api/v1/users/*";
        b.iter(|| {
            evaluate_operator(black_box(test_string), "wildcard not match", black_box(pattern), false)
        })
    });

    group.bench_function("eq_string", |b| {
        b.iter(|| {
            evaluate_operator(black_box("exact-match"), "eq string", black_box("exact-match"), false)
        })
    });

    group.bench_function("contains", |b| {
        b.iter(|| {
            evaluate_operator(black_box("hello world foo bar"), "contains", black_box("world"), false)
        })
    });

    group.bench_function("prefix", |b| {
        b.iter(|| {
            evaluate_operator(black_box("/path/to/resource"), "prefix", black_box("/path"), false)
        })
    });

    group.bench_function("suffix", |b| {
        b.iter(|| {
            evaluate_operator(black_box("file.html"), "suffix", black_box(".html"), false)
        })
    });

    group.finish();
}

criterion_group!(benches, bench_firewall_operators);
criterion_main!(benches);
