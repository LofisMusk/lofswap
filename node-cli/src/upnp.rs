use thiserror::Error;
use tokio::process::Command;
use tokio::time::{sleep, Duration};

#[derive(Debug, Error)]
pub enum UpnpError {
    #[error("io")]
    Io(#[from] std::io::Error),
    #[error("command failed: {0}")]
    Command(String),
}

pub async fn upnp_add(port: u16) -> Result<(), UpnpError> {
    // upnpc -r <port> tcp
    let status = Command::new("upnpc")
        .args(["-r", &port.to_string(), "tcp"])
        .status()
        .await
        .map_err(UpnpError::Io)?;
    if !status.success() {
        return Err(UpnpError::Command("upnpc -r tcp".into()));
    }
    Ok(())
}

pub async fn upnp_delete(port: u16) -> Result<(), UpnpError> {
    // upnpc -d <port> tcp
    let status = Command::new("upnpc")
        .args(["-d", &port.to_string(), "tcp"])
        .status()
        .await
        .map_err(UpnpError::Io)?;
    if !status.success() {
        return Err(UpnpError::Command("upnpc -d tcp".into()));
    }
    Ok(())
}

pub async fn upnp_heartbeat_task(port: u16) {
    // odświeżaj mapowanie cyklicznie
    const UPNP_HEARTBEAT_SECS: u64 = 15 * 60; // 15 min
    loop {
        let _ = upnp_add(port).await;
        sleep(Duration::from_secs(UPNP_HEARTBEAT_SECS)).await;
    }
}
