use std::sync::Arc;
use anyhow::Result;
use tokio::net::TcpListener;
use tracing::{info, error};

use conduit5::config::Config;
use conduit5::whitelist::Whitelist;
use conduit5::socks5;

#[tokio::main]
async fn main() -> Result<()>{
    tracing_subscriber::fmt::init();
    let config = Config::from_file("config.toml").unwrap_or_default();
    let bind = config.bind.unwrap_or_else(|| "127.0.0.1:1080".to_string());

    let wl = Whitelist::from_strings(config.whitelist.unwrap_or_default());
    info!("whitelist: {:?}", wl);
    let whitelist = Arc::new(wl);

    info!("SOCKS5 proxy listening on {}", bind);
    let listener = TcpListener::bind(&bind).await?;

    loop {
        let (socket, peer) = listener.accept().await?;
        let whitelist = whitelist.clone();
        tokio::spawn(async move {
            if let Err(e) = socks5::handle_connection(socket, whitelist).await {
                error!("{} - connection error: {:?}", peer, e);
            }
        });
    }
}