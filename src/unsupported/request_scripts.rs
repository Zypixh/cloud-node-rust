use super::UnsupportedFeature;

pub const FEATURE: UnsupportedFeature = UnsupportedFeature {
    code: "requestScripts",
    reason: "暂不考虑支持边缘请求脚本运行时，scriptsChanged 任务只会记录并标记完成。",
};

pub fn unsupported() -> UnsupportedFeature {
    FEATURE
}
