// Minimal stub for sysproxy to satisfy build
pub struct SavedProxyState;
pub fn take_snapshot() -> SavedProxyState { SavedProxyState }
pub fn enable(_: &str, _: u16) -> anyhow::Result<()> { Ok(()) }
pub fn restore(_: &SavedProxyState) -> anyhow::Result<()> { Ok(()) }
