/// Minimal benchmark proxy — isolates Pingora + cache throughput from GoEdge overhead.
/// Listens on :8080 (HTTP). Forwards all requests to 127.0.0.1:8081 (local origin).
///
/// Usage:
///   1. Start origin:  python3 -m http.server 8081 -d /tmp/bench-origin
///   2. Generate URLs: for i in $(seq 0 9999); do echo "/$i.bin" >> /tmp/urls.txt; done
///   3. Start proxy:   cargo run --bin bench-proxy
///   4. Run oha:       oha -z 30s -c 200 --urls-from-file /tmp/urls.txt http://127.0.0.1:8080

use async_trait::async_trait;
use once_cell::sync::Lazy;
use pingora_cache::lock::CacheLock;
use pingora_core::server::configuration::ServerConf;
use pingora_core::server::Server;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session};
use std::time::Duration;

use cloud_node_rust::cache_manager::CACHE;
use pingora_cache::CacheKey;

static CACHE_LOCK: Lazy<CacheLock> =
    Lazy::new(|| CacheLock::new(std::time::Duration::from_secs(1)));

struct BenchProxy;

#[async_trait]
impl ProxyHttp for BenchProxy {
    type CTX = String;
    fn new_ctx(&self) -> Self::CTX {
        String::new()
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        session.cache.enable(&*CACHE.storage, None, None, Some(&*CACHE_LOCK), None);
        Ok(false)
    }

    fn cache_key_callback(&self, session: &Session, _ctx: &mut Self::CTX) -> Result<CacheKey> {
        let key = session.req_header().uri.path().to_string();
        Ok(CacheKey::new("", key.as_bytes().to_vec(), ""))
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let mut peer = Box::new(HttpPeer::new(("127.0.0.1", 8081), false, "".to_string()));
        peer.options.connection_timeout = Some(Duration::from_secs(3));
        peer.options.idle_timeout = Some(Duration::from_secs(60));
        peer.options.read_timeout = Some(Duration::from_secs(60));
        Ok(peer)
    }

    fn response_cache_filter(
        &self,
        _session: &Session,
        resp: &ResponseHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<pingora_cache::RespCacheable> {
        use pingora_cache::CacheMeta;
        let now = std::time::SystemTime::now();
        let meta = CacheMeta::new(
            now + Duration::from_secs(3600),
            now,
            0,
            0,
            resp.clone(),
        );
        Ok(pingora_cache::RespCacheable::Cacheable(meta))
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        upstream_response.insert_header("x-cache", "MISS").unwrap();
        Ok(())
    }
}

fn main() {
    let mut conf = ServerConf::default();
    conf.threads = num_cpus::get();
    conf.upstream_keepalive_pool_size = 32768;

    let mut server = Server::new_with_opt_and_conf(None, conf);
    server.bootstrap();

    // Force initialization of global cache
    Lazy::force(&CACHE);

    let mut proxy = pingora_proxy::http_proxy_service(&server.configuration, BenchProxy);
    proxy.add_tcp("0.0.0.0:8080");
    server.add_service(proxy);

    eprintln!("Bench proxy ready: :8080 -> origin :8081");
    server.run_forever();
}
