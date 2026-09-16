use crate::config_models::TOAConfig;
use anyhow::{Context, Result, anyhow};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use neli::{
        consts::{nl::NlmF, socket::NlFamily},
        genl::{AttrTypeBuilder, Genlmsghdr, GenlmsghdrBuilder, NlattrBuilder},
        neli_enum,
        nl::NlPayload,
        router::synchronous::NlRouter,
        types::{Buffer, GenlBuffer},
        utils::Groups,
    };
    use std::{
        collections::HashMap,
        fs,
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
        path::{Path, PathBuf},
        process::Command,
        sync::{Mutex, OnceLock},
    };
    use tokio::net::{TcpSocket, lookup_host};

    const FAMILY_NAME: &str = "CLOUD_TOA_SENDER";
    const DEFAULT_MIN_PORT: u16 = 20001;
    const DEFAULT_MAX_PORT: u16 = 20120;
    const MODULE_NAME: &str = "cloud_toa_sender";
    const MODULE_SYSFS_PATH: &str = "/sys/module/cloud_toa_sender";

    #[neli_enum(serialized_type = "u8")]
    enum CloudToaSenderCmd {
        Unspec = 0,
        Add = 1,
        Del = 2,
        Flush = 4,
    }

    impl neli::consts::genl::Cmd for CloudToaSenderCmd {}

    #[neli_enum(serialized_type = "u16")]
    enum CloudToaSenderAttr {
        Unspec = 0,
        LocalPort = 1,
        ClientFamily = 2,
        ClientPort = 3,
        ClientAddr4 = 4,
        ClientAddr6 = 5,
        BackendFamily = 7,
        BackendPort = 8,
        BackendAddr4 = 9,
        BackendAddr6 = 10,
    }

    impl neli::consts::genl::NlAttrType for CloudToaSenderAttr {}

    #[derive(Clone)]
    struct Mapping {
        local_port: u16,
        client_addr: IpAddr,
        client_port: u16,
        backend_addr: SocketAddr,
    }

    struct AllocatorState {
        min_port: u16,
        max_port: u16,
        next_port: u16,
        leases: HashMap<u16, Mapping>,
    }

    impl AllocatorState {
        fn new(min_port: u16, max_port: u16) -> Self {
            Self {
                min_port,
                max_port,
                next_port: min_port,
                leases: HashMap::new(),
            }
        }

        fn configure(&mut self, min_port: u16, max_port: u16) {
            if self.leases.is_empty()
                && (self.min_port != min_port || self.max_port != max_port)
                && min_port > 0
                && min_port <= max_port
            {
                self.min_port = min_port;
                self.max_port = max_port;
                self.next_port = min_port;
            }
        }

        fn allocate(
            &mut self,
            client_addr: IpAddr,
            client_port: u16,
            backend_addr: SocketAddr,
        ) -> Result<Mapping> {
            let capacity = usize::from(self.max_port - self.min_port) + 1;
            for _ in 0..capacity {
                let local_port = self.next_port;
                self.next_port = if self.next_port >= self.max_port {
                    self.min_port
                } else {
                    self.next_port + 1
                };

                if self.leases.contains_key(&local_port) {
                    continue;
                }

                let mapping = Mapping {
                    local_port,
                    client_addr,
                    client_port,
                    backend_addr,
                };
                self.leases.insert(local_port, mapping.clone());
                return Ok(mapping);
            }

            Err(anyhow!(
                "TOA sender port pool exhausted in range {}-{}",
                self.min_port,
                self.max_port
            ))
        }

        fn release(&mut self, local_port: u16) {
            self.leases.remove(&local_port);
        }
    }

    fn allocator() -> &'static Mutex<AllocatorState> {
        static ALLOCATOR: OnceLock<Mutex<AllocatorState>> = OnceLock::new();
        ALLOCATOR
            .get_or_init(|| Mutex::new(AllocatorState::new(DEFAULT_MIN_PORT, DEFAULT_MAX_PORT)))
    }

    struct KernelClient {
        router: NlRouter,
        family_id: u16,
    }

    impl KernelClient {
        fn connect() -> Result<Self> {
            let (router, _) = NlRouter::connect(NlFamily::Generic, Some(0), Groups::empty())
                .context("failed to connect TOA sender generic netlink socket")?;
            let family_id = router.resolve_genl_family(FAMILY_NAME).with_context(|| {
                format!("failed to resolve generic netlink family {}", FAMILY_NAME)
            })?;
            Ok(Self { router, family_id })
        }

        fn add(&self, mapping: &Mapping) -> Result<()> {
            let attrs = build_mapping_attrs(mapping);
            let msg: Genlmsghdr<CloudToaSenderCmd, CloudToaSenderAttr> =
                GenlmsghdrBuilder::default()
                    .cmd(CloudToaSenderCmd::Add)
                    .version(1)
                    .attrs(attrs)
                    .build()
                    .context("failed to build TOA sender ADD request")?;

            let mut recv = self
                .router
                .send::<_, _, u16, Genlmsghdr<CloudToaSenderCmd, CloudToaSenderAttr>>(
                    self.family_id,
                    NlmF::ACK,
                    NlPayload::Payload(msg),
                )
                .context("failed to send TOA sender ADD request")?;
            let _ = recv.next();
            Ok(())
        }

        fn del(&self, local_port: u16) -> Result<()> {
            let attrs = std::iter::once(
                NlattrBuilder::default()
                    .nla_type(
                        AttrTypeBuilder::default()
                            .nla_type(CloudToaSenderAttr::LocalPort)
                            .build()
                            .unwrap(),
                    )
                    .nla_payload(local_port)
                    .build()
                    .unwrap(),
            )
            .collect::<GenlBuffer<_, _>>();

            let msg: Genlmsghdr<CloudToaSenderCmd, CloudToaSenderAttr> =
                GenlmsghdrBuilder::default()
                    .cmd(CloudToaSenderCmd::Del)
                    .version(1)
                    .attrs(attrs)
                    .build()
                    .context("failed to build TOA sender DEL request")?;

            let mut recv = self
                .router
                .send::<_, _, u16, Genlmsghdr<CloudToaSenderCmd, CloudToaSenderAttr>>(
                    self.family_id,
                    NlmF::ACK,
                    NlPayload::Payload(msg),
                )
                .context("failed to send TOA sender DEL request")?;
            let _ = recv.next();
            Ok(())
        }

        fn flush(&self) -> Result<()> {
            let msg: Genlmsghdr<CloudToaSenderCmd, CloudToaSenderAttr> =
                GenlmsghdrBuilder::default()
                    .cmd(CloudToaSenderCmd::Flush)
                    .version(1)
                    .attrs(std::iter::empty().collect::<GenlBuffer<CloudToaSenderAttr, Buffer>>())
                    .build()
                    .context("failed to build TOA sender FLUSH request")?;

            let mut recv = self
                .router
                .send::<_, _, u16, Genlmsghdr<CloudToaSenderCmd, CloudToaSenderAttr>>(
                    self.family_id,
                    NlmF::ACK,
                    NlPayload::Payload(msg),
                )
                .context("failed to send TOA sender FLUSH request")?;
            let _ = recv.next();
            Ok(())
        }
    }

    fn build_mapping_attrs(mapping: &Mapping) -> GenlBuffer<CloudToaSenderAttr, Buffer> {
        let client_family = match mapping.client_addr {
            IpAddr::V4(_) => libc::AF_INET as u16,
            IpAddr::V6(_) => libc::AF_INET6 as u16,
        };
        let backend_family = match mapping.backend_addr {
            SocketAddr::V4(_) => libc::AF_INET as u16,
            SocketAddr::V6(_) => libc::AF_INET6 as u16,
        };

        let mut attrs = vec![
            NlattrBuilder::default()
                .nla_type(
                    AttrTypeBuilder::default()
                        .nla_type(CloudToaSenderAttr::LocalPort)
                        .build()
                        .unwrap(),
                )
                .nla_payload(mapping.local_port)
                .build()
                .unwrap(),
            NlattrBuilder::default()
                .nla_type(
                    AttrTypeBuilder::default()
                        .nla_type(CloudToaSenderAttr::ClientFamily)
                        .build()
                        .unwrap(),
                )
                .nla_payload(client_family)
                .build()
                .unwrap(),
            NlattrBuilder::default()
                .nla_type(
                    AttrTypeBuilder::default()
                        .nla_type(CloudToaSenderAttr::ClientPort)
                        .build()
                        .unwrap(),
                )
                .nla_payload(mapping.client_port)
                .build()
                .unwrap(),
            NlattrBuilder::default()
                .nla_type(
                    AttrTypeBuilder::default()
                        .nla_type(CloudToaSenderAttr::BackendFamily)
                        .build()
                        .unwrap(),
                )
                .nla_payload(backend_family)
                .build()
                .unwrap(),
            NlattrBuilder::default()
                .nla_type(
                    AttrTypeBuilder::default()
                        .nla_type(CloudToaSenderAttr::BackendPort)
                        .build()
                        .unwrap(),
                )
                .nla_payload(mapping.backend_addr.port())
                .build()
                .unwrap(),
        ];

        match mapping.client_addr {
            IpAddr::V4(addr) => attrs.push(
                NlattrBuilder::default()
                    .nla_type(
                        AttrTypeBuilder::default()
                            .nla_type(CloudToaSenderAttr::ClientAddr4)
                            .build()
                            .unwrap(),
                    )
                    .nla_payload(u32::from_ne_bytes(addr.octets()).to_be())
                    .build()
                    .unwrap(),
            ),
            IpAddr::V6(addr) => attrs.push(
                NlattrBuilder::default()
                    .nla_type(
                        AttrTypeBuilder::default()
                            .nla_type(CloudToaSenderAttr::ClientAddr6)
                            .build()
                            .unwrap(),
                    )
                    .nla_payload(addr.octets().to_vec())
                    .build()
                    .unwrap(),
            ),
        }

        match mapping.backend_addr {
            SocketAddr::V4(addr) => attrs.push(
                NlattrBuilder::default()
                    .nla_type(
                        AttrTypeBuilder::default()
                            .nla_type(CloudToaSenderAttr::BackendAddr4)
                            .build()
                            .unwrap(),
                    )
                    .nla_payload(u32::from_ne_bytes(addr.ip().octets()).to_be())
                    .build()
                    .unwrap(),
            ),
            SocketAddr::V6(addr) => attrs.push(
                NlattrBuilder::default()
                    .nla_type(
                        AttrTypeBuilder::default()
                            .nla_type(CloudToaSenderAttr::BackendAddr6)
                            .build()
                            .unwrap(),
                    )
                    .nla_payload(addr.ip().octets().to_vec())
                    .build()
                    .unwrap(),
            ),
        }

        attrs
            .into_iter()
            .collect::<GenlBuffer<CloudToaSenderAttr, Buffer>>()
    }

    fn configured_port_range(config: &TOAConfig) -> (u16, u16) {
        let min = config.min_port.unwrap_or(DEFAULT_MIN_PORT);
        let max = config.max_port.unwrap_or(DEFAULT_MAX_PORT);
        if min == 0 || min > max {
            (DEFAULT_MIN_PORT, DEFAULT_MAX_PORT)
        } else {
            (min, max)
        }
    }

    fn module_loaded() -> bool {
        Path::new(MODULE_SYSFS_PATH).exists()
    }

    fn sender_root_candidates() -> Vec<PathBuf> {
        let mut candidates = Vec::new();
        if let Ok(dir) = std::env::var("CLOUD_NODE_TOA_SENDER_DIR") {
            candidates.push(PathBuf::from(dir));
        }
        if let Ok(current_dir) = std::env::current_dir() {
            candidates.push(current_dir.join("toa-sender"));
        }
        if let Ok(exe) = std::env::current_exe()
            && let Some(parent) = exe.parent()
        {
            candidates.push(parent.join("toa-sender"));
            if let Some(grand) = parent.parent() {
                candidates.push(grand.join("toa-sender"));
            }
        }
        candidates
    }

    fn find_sender_root() -> Option<PathBuf> {
        sender_root_candidates()
            .into_iter()
            .find(|candidate| candidate.join("Makefile").exists())
    }

    fn sender_module_candidates(root: &Path) -> Vec<PathBuf> {
        let mut candidates = vec![root.join(format!("{MODULE_NAME}.ko"))];
        if let Ok(kernel_release) = fs::read_to_string("/proc/sys/kernel/osrelease") {
            let release = kernel_release.trim();
            if !release.is_empty() {
                candidates.push(
                    root.join(format!("{MODULE_NAME}.ko"))
                        .with_file_name(format!("{MODULE_NAME}.ko")),
                );
                candidates.push(root.join(format!("{MODULE_NAME}.ko")));
                candidates.push(root.join(format!("{MODULE_NAME}.ko.{release}")));
            }
        }
        candidates
    }

    fn module_binary_exists(root: &Path) -> Option<PathBuf> {
        sender_module_candidates(root)
            .into_iter()
            .find(|candidate| candidate.exists())
    }

    fn run_command(command: &mut Command, context: &str) -> Result<()> {
        let output = command
            .output()
            .with_context(|| format!("failed to spawn {}", context))?;
        if output.status.success() {
            return Ok(());
        }
        Err(anyhow!(
            "{} failed with status {}: stdout={} stderr={}",
            context,
            output.status,
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }

    fn ensure_sender_module_ready() -> Result<()> {
        if module_loaded() {
            return Ok(());
        }

        let sender_root =
            find_sender_root().ok_or_else(|| anyhow!("failed to locate toa-sender directory"))?;

        if module_binary_exists(&sender_root).is_none() {
            run_command(
                Command::new("make").current_dir(&sender_root),
                "building cloud_toa_sender.ko",
            )?;
        }

        let module_path = module_binary_exists(&sender_root).ok_or_else(|| {
            anyhow!(
                "cloud_toa_sender.ko not found after build in {}",
                sender_root.display()
            )
        })?;

        run_command(
            Command::new("insmod")
                .arg(&module_path)
                .arg("option_type_v4=254")
                .arg("option_type_v6=254"),
            "loading cloud_toa_sender.ko",
        )?;

        if !module_loaded() {
            return Err(anyhow!(
                "cloud_toa_sender.ko load command returned success but module is not visible in {}",
                MODULE_SYSFS_PATH
            ));
        }

        Ok(())
    }

    pub async fn maybe_prepare_runtime(toa_config: Option<TOAConfig>) -> Result<()> {
        let enabled = toa_config.as_ref().map(|cfg| cfg.is_on).unwrap_or(false);
        if !enabled || module_loaded() {
            return Ok(());
        }

        static PREPARE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        tokio::task::spawn_blocking(|| {
            let guard = PREPARE_LOCK
                .get_or_init(|| Mutex::new(()))
                .lock()
                .map_err(|_| anyhow!("TOA prepare lock poisoned"))?;
            if module_loaded() {
                drop(guard);
                return Ok(());
            }
            let result = ensure_sender_module_ready();
            drop(guard);
            result
        })
        .await
        .context("failed to join TOA sender prepare task")?
    }

    pub async fn unregister_toa_port(toa_config: Option<TOAConfig>, local_port: u16) -> Result<()> {
        let enabled = toa_config.as_ref().map(|cfg| cfg.is_on).unwrap_or(false);
        if !enabled {
            return Ok(());
        }

        tokio::task::spawn_blocking(move || {
            let client = KernelClient::connect()?;
            client.del(local_port)?;
            let mut guard = allocator()
                .lock()
                .map_err(|_| anyhow!("TOA allocator state poisoned"))?;
            guard.release(local_port);
            Ok::<(), anyhow::Error>(())
        })
        .await
        .context("failed to join TOA sender release task")?
    }

    pub async fn connect_with_toa(
        backend_addr: &str,
        remote_addr: SocketAddr,
        toa_config: Option<TOAConfig>,
        connect_timeout: Duration,
    ) -> Result<TcpStream> {
        let enabled = toa_config.as_ref().map(|cfg| cfg.is_on).unwrap_or(false);
        if !enabled {
            return timeout(connect_timeout, TcpStream::connect(backend_addr))
                .await
                .with_context(|| format!("timed out connecting upstream {}", backend_addr))?
                .with_context(|| format!("failed to connect upstream {}", backend_addr));
        }

        let config = toa_config.expect("checked above");
        maybe_prepare_runtime(Some(config.clone())).await?;
        let backend = lookup_host(backend_addr)
            .await
            .with_context(|| format!("failed to resolve TOA upstream {}", backend_addr))?
            .next()
            .ok_or_else(|| {
                anyhow!(
                    "no socket address resolved for TOA upstream {}",
                    backend_addr
                )
            })?;

        static FLUSHED: OnceLock<()> = OnceLock::new();
        if FLUSHED.get().is_none() {
            tokio::task::spawn_blocking(|| {
                let client = KernelClient::connect()?;
                client.flush()
            })
            .await
            .context("failed to join TOA sender flush task")??;
            let _ = FLUSHED.set(());
        }
        let (min_port, max_port) = configured_port_range(&config);

        let mapping = tokio::task::spawn_blocking(move || {
            let client = KernelClient::connect()?;
            let mut guard = allocator()
                .lock()
                .map_err(|_| anyhow!("TOA allocator state poisoned"))?;
            guard.configure(min_port, max_port);
            let mapping = guard.allocate(remote_addr.ip(), remote_addr.port(), backend)?;
            if let Err(err) = client.add(&mapping) {
                guard.release(mapping.local_port);
                return Err(err);
            }
            Ok::<Mapping, anyhow::Error>(mapping)
        })
        .await
        .context("failed to join TOA sender allocate task")??;

        let socket = match backend {
            SocketAddr::V4(_) => TcpSocket::new_v4().context("failed to create IPv4 TOA socket")?,
            SocketAddr::V6(_) => TcpSocket::new_v6().context("failed to create IPv6 TOA socket")?,
        };

        let bind_result = match backend {
            SocketAddr::V4(_) => socket.bind(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::UNSPECIFIED,
                mapping.local_port,
            ))),
            SocketAddr::V6(_) => socket.bind(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::UNSPECIFIED,
                mapping.local_port,
                0,
                0,
            ))),
        };
        if let Err(err) = bind_result {
            let _ = unregister_toa_port(Some(config.clone()), mapping.local_port).await;
            return Err(err).context("failed to bind allocated TOA sender local port");
        }

        let connect_result = timeout(connect_timeout, socket.connect(backend))
            .await
            .with_context(|| format!("timed out connecting TOA upstream {}", backend_addr))?
            .with_context(|| format!("failed to connect TOA upstream {}", backend_addr));

        if connect_result.is_err() {
            let _ = unregister_toa_port(Some(config), mapping.local_port).await;
        }

        connect_result
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::*;

    pub async fn maybe_prepare_runtime(_toa_config: Option<TOAConfig>) -> Result<()> {
        Ok(())
    }

    pub async fn unregister_toa_port(
        _toa_config: Option<TOAConfig>,
        _local_port: u16,
    ) -> Result<()> {
        Ok(())
    }

    pub async fn connect_with_toa(
        backend_addr: &str,
        _remote_addr: SocketAddr,
        toa_config: Option<TOAConfig>,
        connect_timeout: Duration,
    ) -> Result<TcpStream> {
        let enabled = toa_config.as_ref().map(|cfg| cfg.is_on).unwrap_or(false);
        if !enabled {
            return timeout(connect_timeout, TcpStream::connect(backend_addr))
                .await
                .with_context(|| format!("timed out connecting upstream {}", backend_addr))?
                .with_context(|| format!("failed to connect upstream {}", backend_addr));
        }

        Err(anyhow!(
            "TOA is enabled, but sender-side TOA requires Linux; build and run the proxy on Linux with cloud_toa_sender.ko loaded"
        ))
    }
}

pub use imp::{connect_with_toa, maybe_prepare_runtime, unregister_toa_port};

// ---------------------------------------------------------------------------
// T4-6: upstream connect surface — kernel socket vs AF_XDP dataplane.
// ---------------------------------------------------------------------------

/// TOA TCP option bytes for the AF_XDP upstream path — the same wire
/// format `cloud_toa_sender.ko` writes into SYNs (kind 254):
/// v4 = `[254, 8, port_be16, ip_be32]` (8B), v6 = `[254, 20, port_be16,
/// ip6]` (20B). Injected verbatim via smoltcp SYN extra options; the
/// genl mapping/port allocator is bypassed entirely on this path.
pub fn toa_syn_option_bytes(client: SocketAddr) -> Vec<u8> {
    let mut option = Vec::with_capacity(20);
    match client.ip() {
        std::net::IpAddr::V4(ip) => {
            option.extend_from_slice(&[254, 8]);
            option.extend_from_slice(&client.port().to_be_bytes());
            option.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            option.extend_from_slice(&[254, 20]);
            option.extend_from_slice(&client.port().to_be_bytes());
            option.extend_from_slice(&ip.octets());
        }
    }
    option
}

/// T4-6: upstream TCP stream returned by [`connect_upstream`]. The
/// kernel variant is the pre-existing path; `AfXdp` is a node-dialed
/// smoltcp-edge flow whose lifecycle (source port, XDP_OUT_CT row) is
/// owned by the AF_XDP dial registry and released on session reap.
pub enum UpstreamL4Stream {
    Kernel(TcpStream),
    #[cfg(target_os = "linux")]
    AfXdp(crate::xdp::af_xdp::AfXdpTcpStream),
}

impl UpstreamL4Stream {
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        match self {
            Self::Kernel(stream) => stream.local_addr(),
            #[cfg(target_os = "linux")]
            Self::AfXdp(stream) => stream.local_addr(),
        }
    }

    pub fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        match self {
            Self::Kernel(stream) => stream.peer_addr(),
            #[cfg(target_os = "linux")]
            Self::AfXdp(stream) => stream.peer_addr(),
        }
    }

    /// Kernel-TOA local port to release via `unregister_toa_port` —
    /// `None` on the AF_XDP path, whose source port is owned by the dial
    /// registry, never by the kernel TOA allocator.
    pub fn kernel_toa_port(&self) -> Option<u16> {
        match self {
            Self::Kernel(stream) => stream.local_addr().ok().map(|addr| addr.port()),
            #[cfg(target_os = "linux")]
            Self::AfXdp(_) => None,
        }
    }

    /// Relay socket tuning. Kernel sockets get the sysctl-level options;
    /// AF_XDP flows already run nodelay at the smoltcp socket and are
    /// buffer-bounded by the reactor/memory governor instead of
    /// SO_*BUF setsockopts.
    pub fn configure_relay_socket(&self) {
        match self {
            Self::Kernel(stream) => crate::tcp_proxy::configure_relay_tcp_socket(stream),
            #[cfg(target_os = "linux")]
            Self::AfXdp(_) => {}
        }
    }

    /// Wrap into a pingora L4 stream. The AF_XDP variant reuses the same
    /// `virtual_l4_stream` bridge as the inbound dataplane; `peer_addr`
    /// (the upstream endpoint) is stamped into the socket digest.
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
    pub fn into_pingora_stream(
        self,
        peer_addr: SocketAddr,
    ) -> pingora_core::protocols::l4::stream::Stream {
        match self {
            Self::Kernel(stream) => {
                pingora_core::protocols::l4::stream::Stream::from(stream)
            }
            #[cfg(target_os = "linux")]
            Self::AfXdp(stream) => {
                crate::xdp::af_xdp::virtual_l4_stream(stream, peer_addr)
            }
        }
    }
}

impl tokio::io::AsyncRead for UpstreamL4Stream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Kernel(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
            #[cfg(target_os = "linux")]
            Self::AfXdp(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for UpstreamL4Stream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Kernel(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
            #[cfg(target_os = "linux")]
            Self::AfXdp(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Kernel(stream) => std::pin::Pin::new(stream).poll_flush(cx),
            #[cfg(target_os = "linux")]
            Self::AfXdp(stream) => std::pin::Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Kernel(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
            #[cfg(target_os = "linux")]
            Self::AfXdp(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// T4-6: unified upstream connect. When `xdp.upstream.mode=afxdp` the
/// dial runs through the AF_XDP registry (explicit error when it is not
/// armed — never a silent kernel fallback); otherwise this is the
/// existing kernel/TOA path.
pub async fn connect_upstream(
    backend_addr: &str,
    remote_addr: SocketAddr,
    toa_config: Option<TOAConfig>,
    connect_timeout: Duration,
) -> Result<UpstreamL4Stream> {
    #[cfg(target_os = "linux")]
    {
        if crate::xdp::afxdp_upstream_selected() {
            return connect_upstream_afxdp(
                backend_addr,
                remote_addr,
                toa_config,
                connect_timeout,
            )
            .await;
        }
    }
    connect_with_toa(backend_addr, remote_addr, toa_config, connect_timeout)
        .await
        .map(UpstreamL4Stream::Kernel)
}

#[cfg(target_os = "linux")]
async fn connect_upstream_afxdp(
    backend_addr: &str,
    remote_addr: SocketAddr,
    toa_config: Option<TOAConfig>,
    connect_timeout: Duration,
) -> Result<UpstreamL4Stream> {
    let backend = tokio::net::lookup_host(backend_addr)
        .await
        .with_context(|| format!("failed to resolve AF_XDP upstream {}", backend_addr))?
        .next()
        .ok_or_else(|| anyhow!("no socket address resolved for AF_XDP upstream {backend_addr}"))?;
    let toa_enabled = toa_config.map(|cfg| cfg.is_on).unwrap_or(false);
    // TOA on the AF_XDP path is a SYN option we write ourselves — the
    // cloud_toa_sender kernel module never sees these packets (no
    // LOCAL_OUT traversal), and its port allocator is not involved.
    let syn_extra_options = if toa_enabled {
        toa_syn_option_bytes(remote_addr)
    } else {
        Vec::new()
    };
    let stream = timeout(
        connect_timeout,
        crate::xdp::af_xdp_dial_tcp(backend, syn_extra_options),
    )
    .await
    .with_context(|| format!("timed out connecting AF_XDP upstream {}", backend_addr))?
    .with_context(|| format!("failed to connect AF_XDP upstream {}", backend_addr))?;
    Ok(UpstreamL4Stream::AfXdp(stream))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toa_syn_option_bytes_v4_wire_format() {
        let client: SocketAddr = "203.0.113.7:54321".parse().unwrap();
        let bytes = toa_syn_option_bytes(client);
        assert_eq!(
            bytes,
            vec![
                254, 8, // kind + length
                0xD4, 0x31, // 54321 be16
                203, 0, 113, 7, // client IPv4
            ]
        );
    }

    #[test]
    fn toa_syn_option_bytes_v6_wire_format() {
        let client: SocketAddr = "[2001:db8::1]:4321".parse().unwrap();
        let bytes = toa_syn_option_bytes(client);
        let mut expected = vec![254, 20];
        expected.extend_from_slice(&4321u16.to_be_bytes());
        expected.extend_from_slice(&"2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
        assert_eq!(bytes, expected);
    }

    #[tokio::test]
    async fn connect_upstream_kernel_mode_returns_kernel_stream() {
        let _guard = crate::runtime_mode::runtime_config_test_guard();
        crate::runtime_mode::RuntimeConfig::set_current(
            crate::runtime_mode::RuntimeConfig::default(),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = listener.local_addr().unwrap().to_string();
        let client: SocketAddr = "198.51.100.9:4444".parse().unwrap();
        let stream = connect_upstream(
            &backend_addr,
            client,
            None,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        let expected: SocketAddr = backend_addr.parse().unwrap();
        assert_eq!(stream.peer_addr().unwrap(), expected);
        // Kernel streams keep the kernel TOA port contract — the caller
        // releases it via `unregister_toa_port` (a no-op when TOA is off).
        assert!(stream.kernel_toa_port().is_some());
        // Kernel streams still wrap into a plain pingora stream.
        let _pingora = stream.into_pingora_stream(expected);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn connect_upstream_afxdp_mode_without_registry_is_explicit_error() {
        let _guard = crate::runtime_mode::runtime_config_test_guard();
        let mut config = crate::runtime_mode::RuntimeConfig::default();
        config.xdp.upstream = Some(crate::runtime_mode::XdpUpstreamSettings {
            mode: crate::runtime_mode::XdpUpstreamMode::Afxdp,
            ..Default::default()
        });
        crate::runtime_mode::RuntimeConfig::set_current(config);
        let client: SocketAddr = "198.51.100.9:4444".parse().unwrap();
        let err = match connect_upstream(
            "127.0.0.1:1",
            client,
            None,
            Duration::from_secs(1),
        )
        .await
        {
            Ok(_) => panic!("afxdp mode without a live registry must fail closed"),
            Err(err) => err,
        };
        let message = format!("{err:#}");
        assert!(
            message.contains("failed to connect AF_XDP upstream"),
            "unexpected error: {message}"
        );
    }
}
