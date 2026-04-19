fn main() {
    println!("UTC: {}", chrono::Utc::now());
    println!("Local: {}", chrono::Local::now());
    println!("Local iso: {}", chrono::Local::now().format("%Y-%m-%dT%H:%M:%S.000%:z"));
}
