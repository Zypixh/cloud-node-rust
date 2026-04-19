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

    group.finish();
}

criterion_group!(benches, bench_firewall_operators);
criterion_main!(benches);
