use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct NodePaths {
    root: PathBuf,
}

impl NodePaths {
    pub fn current() -> Self {
        let root = std::env::var_os("CLOUD_NODE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
        Self { root }
    }

    pub fn from_root(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn runtime_root(&self) -> &Path {
        &self.root
    }

    pub fn config_dir(&self) -> PathBuf {
        self.root.join("configs")
    }

    pub fn data_dir(&self) -> PathBuf {
        self.root.join("data")
    }

    pub fn logs_dir(&self) -> PathBuf {
        self.root.join("logs")
    }

    pub fn api_config_file(&self) -> PathBuf {
        self.config_dir().join("api_node.yaml")
    }

    pub fn legacy_api_config_file(&self) -> PathBuf {
        self.root.join("api_node.yaml")
    }

    pub fn pid_file(&self) -> PathBuf {
        self.data_dir().join("cloud-node.pid")
    }

    pub fn run_log_file(&self) -> PathBuf {
        self.logs_dir().join("run.log")
    }

    pub fn state_file(&self) -> PathBuf {
        self.data_dir().join("state.json")
    }

    pub fn blocked_ips_file(&self) -> PathBuf {
        self.data_dir().join("blocked_ips.json")
    }

    pub fn metrics_db_dir(&self) -> PathBuf {
        self.data_dir().join("metrics.db")
    }

    pub fn cache_dir(&self) -> PathBuf {
        self.data_dir().join("cache")
    }

    pub fn geoip_city_file(&self) -> PathBuf {
        self.data_dir().join("GeoLite2-City.mmdb")
    }

    pub fn geoip_asn_file(&self) -> PathBuf {
        self.data_dir().join("GeoLite2-ASN.mmdb")
    }

    pub fn geoip_country_file(&self) -> PathBuf {
        self.data_dir().join("GeoLite2-Country.mmdb")
    }

    pub fn legacy_pid_file(&self) -> PathBuf {
        self.root.join("../data/cloud-node.pid")
    }

    pub fn legacy_state_file(&self) -> PathBuf {
        self.root.join("../data/state.json")
    }

    pub fn legacy_blocked_ips_file(&self) -> PathBuf {
        self.root.join("../data/blocked_ips.json")
    }

    pub fn legacy_metrics_db_dir(&self) -> PathBuf {
        self.root.join("../data/metrics.db")
    }

    pub fn legacy_cache_dir(&self) -> PathBuf {
        self.root.join("configs/cache/disk")
    }

    pub fn legacy_geoip_city_file(&self) -> PathBuf {
        self.root.join("GeoLite2-City.mmdb")
    }

    pub fn legacy_geoip_asn_file(&self) -> PathBuf {
        self.root.join("GeoLite2-ASN.mmdb")
    }

    pub fn legacy_geoip_country_file(&self) -> PathBuf {
        self.root.join("GeoLite2-Country.mmdb")
    }

    pub fn api_config_candidates(&self) -> Vec<PathBuf> {
        vec![
            self.api_config_file(),
            self.legacy_api_config_file(),
            self.root.join("../configs/api_node.yaml"),
            self.root.join("cloud-node/configs/api_node.yaml"),
        ]
    }

    pub fn pid_file_candidates(&self) -> Vec<PathBuf> {
        vec![self.pid_file(), self.legacy_pid_file()]
    }

    pub fn state_file_candidates(&self) -> Vec<PathBuf> {
        vec![self.state_file(), self.legacy_state_file()]
    }

    pub fn blocked_ips_file_candidates(&self) -> Vec<PathBuf> {
        vec![self.blocked_ips_file(), self.legacy_blocked_ips_file()]
    }

    pub fn metrics_db_candidates(&self) -> Vec<PathBuf> {
        vec![self.metrics_db_dir(), self.legacy_metrics_db_dir()]
    }

    pub fn geoip_city_candidates(&self) -> Vec<PathBuf> {
        vec![self.geoip_city_file(), self.legacy_geoip_city_file()]
    }

    pub fn geoip_asn_candidates(&self) -> Vec<PathBuf> {
        vec![self.geoip_asn_file(), self.legacy_geoip_asn_file()]
    }

    pub fn geoip_country_candidates(&self) -> Vec<PathBuf> {
        vec![self.geoip_country_file(), self.legacy_geoip_country_file()]
    }

    pub fn ensure_runtime_dirs(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(self.config_dir())?;
        std::fs::create_dir_all(self.data_dir())?;
        std::fs::create_dir_all(self.logs_dir())?;
        Ok(())
    }
}

pub fn first_existing(paths: &[PathBuf]) -> Option<PathBuf> {
    paths.iter().find(|path| path.exists()).cloned()
}
