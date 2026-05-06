use super::UnsupportedFeature;

pub const FEATURE: UnsupportedFeature = UnsupportedFeature {
    code: "ipLibraryUpdate",
    reason: "暂不考虑完善完整 IP 库更新器。现有 GeoIP 文件同步能力仅作为基础辅助能力保留。",
};

pub fn unsupported() -> UnsupportedFeature {
    FEATURE
}
