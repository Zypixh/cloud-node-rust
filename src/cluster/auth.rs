pub fn enabled() -> bool {
    crate::runtime_mode::RuntimeConfig::current_is_rke2()
}
