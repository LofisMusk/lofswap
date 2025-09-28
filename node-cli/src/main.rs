mod app;
mod peers;
mod upnp;
mod rpc;
mod mine;

use clap::Parser;
use anyhow::Result;
use std::net::SocketAddr;

#[derive(Parser, Debug)]
#[command(name="node-cli")]
struct Cli {
    #[arg(long, default_value = "0.0.0.0:6060")]
    rpc_bind: String,
    #[arg(long, default_value_t = 6000)]
    p2p_port: u16,
    #[arg(long, default_value_t = false)]
    mine: bool,
    #[arg(long, default_value_t = false)]
    no_upnp: bool,
    /// Klucz prywatny lidera (hex) – potrzebny, gdy nasz węzeł wygra key‑blok i chcemy emitować mikrobloki
    #[arg(long)]
    leader_sk_hex: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let mut st = app::AppState::default();
    st.rpc_port = cli.rpc_bind.split(':').last().unwrap_or("6060").parse().unwrap_or(6060);
    st.p2p_port = cli.p2p_port;

    // wczytaj peers
    {
        let mut peers = st.peers.lock().await;
        *peers = peers::PeersDb::load().await;
    }

    // TODO: IMPLEMENT THIS

    // UPnP (opcjonalnie)
  //  if !cli.no_upnp {
  //      if let Some(pub_ip) = upnp::upnp_add(cli.p2p_port).await {
  //          st.observed_ip = pub_ip;
  //          tokio::spawn(upnp::upnp_heartbeat_task(cli.p2p_port));
  //      }
  //  }

    // RPC
    let bind: SocketAddr = cli.rpc_bind.parse().expect("invalid rpc_bind");
    tokio::spawn(rpc::serve_rpc(st.clone(), bind));

    // Kopanie key‑bloków
    if cli.mine {
        let miner_id = st.observed_ip.clone();
        tokio::spawn(mine::mine_key_loop(st.clone(), miner_id));
    }

    // Produkcja mikrobloków (jeśli podano klucz lidera)
    if let Some(sk) = cli.leader_sk_hex {
        tokio::spawn(mine::micro_leader_loop(st.clone(), sk));
    }

    futures::future::pending::<()>().await;
    #[allow(unreachable_code)]
    Ok(())
}
