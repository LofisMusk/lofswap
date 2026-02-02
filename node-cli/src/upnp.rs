use std::sync::Arc;

use easy_upnp::{UpnpConfig as EasyConfig, add_ports, delete_ports};
use igd::{PortMappingProtocol, aio::search_gateway};
use local_ip_address::local_ip;

pub async fn setup_upnp(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    match try_igd_upnp(port).await {
        Ok(_) => return Ok(()),
        Err(e) => {
            if cfg!(debug_assertions) {
                eprintln!("[DEBUG] IGD UPnP failed: {} - trying easy_upnp fallback", e);
            }
        }
    }

    let cfg = Arc::new(EasyConfig {
        address: None,
        port,
        protocol: easy_upnp::PortMappingProtocol::TCP,
        duration: 3600,
        comment: "lofswap node".to_string(),
    });

    {
        let cfg_for_cleanup = cfg.clone();
        if let Err(e) = ctrlc::set_handler(move || {
            let cleanup_cfg = easy_upnp::UpnpConfig {
                address: cfg_for_cleanup.address.clone(),
                port: cfg_for_cleanup.port,
                protocol: cfg_for_cleanup.protocol,
                duration: cfg_for_cleanup.duration,
                comment: cfg_for_cleanup.comment.clone(),
            };
            for result in delete_ports(std::iter::once(cleanup_cfg)) {
                match result {
                    Ok(_) => println!("Easy UPnP: port {} removed", port),
                    Err(e) => eprintln!("Easy UPnP: error removing port: {}", e),
                }
            }
            std::process::exit(0);
        }) {
            eprintln!("Failed to set SIGINT handler: {}", e);
        }
    }

    for result in add_ports(std::iter::once(EasyConfig {
        address: cfg.address.clone(),
        port: cfg.port,
        protocol: cfg.protocol,
        duration: cfg.duration,
        comment: cfg.comment.clone(),
    })) {
        match result {
            Ok(_) => {
                println!("Port {} forwarded (Easy UPnP fallback)", port);
                return Ok(());
            }
            Err(e) => eprintln!("Easy UPnP: port forwarding error: {}", e),
        }
    }

    Err("Failed to forward port through any UPnP mechanism".into())
}

pub async fn try_igd_upnp(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let gateway = search_gateway(Default::default()).await?;
    let local_ip = local_ip()?;
    let ip = match local_ip {
        std::net::IpAddr::V4(ipv4) => ipv4,
        _ => return Err("Only IPv4 supported".into()),
    };

    let socket = std::net::SocketAddrV4::new(ip, port);
    gateway
        .add_port(PortMappingProtocol::TCP, port, socket, 3600, "lofswap node")
        .await?;

    println!("Port {} forwarded to {} (IGD)", port, socket);
    Ok(())
}
