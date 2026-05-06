use super::UnsupportedFeature;

pub const FEATURE: UnsupportedFeature = UnsupportedFeature {
    code: "staticFiles",
    reason: "暂不考虑支持本地静态文件站点服务。当前节点定位为代理、缓存和边缘安全运行时。",
};

pub fn unsupported() -> UnsupportedFeature {
    FEATURE
}
