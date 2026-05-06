use super::UnsupportedFeature;

pub const FEATURE: UnsupportedFeature = UnsupportedFeature {
    code: "autoUpgrade",
    reason: "暂不考虑支持节点自升级。发布、替换二进制和重启流程由外部部署系统负责。",
};

pub fn unsupported() -> UnsupportedFeature {
    FEATURE
}
