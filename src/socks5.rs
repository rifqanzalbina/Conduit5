use anyhow::{anyhow, Result};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpStream};
use tracing::debug;

use crate::whitelist::Whitelist;

const SOCKS5_VER: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;

pub async fn handle_connection(mut client: TcpStream, whitelist: Arc<Whitelist>) -> Result<()> {
    // 1) Handshake
    let ver = client.read_u8().await?;
    if ver != SOCKS5_VER {
        return Err(anyhow!("unsupported socks version: {}", ver));
    }
    let nmethods = client.read_u8().await? as usize;
    let mut methods = vec![0u8; nmethods];
    client.read_exact(&mut methods).await?;

    // Reply: NO AUTH
    client.write_all(&[SOCKS5_VER, METHOD_NO_AUTH]).await?;

    // 2) Request
    let ver = client.read_u8().await?;
    if ver != SOCKS5_VER {
        return Err(anyhow!("unsupported socks version in request: {}", ver));
    }
    let cmd = client.read_u8().await?;
    let _rsv = client.read_u8().await?;
    let atyp = client.read_u8().await?;

    let (addr, port) = match atyp {
        0x01 => {
            // IPv4
            let mut b = [0u8; 4];
            client.read_exact(&mut b).await?;
            let ip = IpAddr::from(b);
            let port = client.read_u16().await?;
            (ip.to_string(), port)
        }
        0x03 => {
            // Domain
            let len = client.read_u8().await? as usize;
            let mut buf = vec![0u8; len];
            client.read_exact(&mut buf).await?;
            let domain = String::from_utf8(buf)?;
            let port = client.read_u16().await?;
            (domain, port)
        }
        0x04 => {
            // IPv6
            let mut b = [0u8; 16];
            client.read_exact(&mut b).await?;
            let ip = IpAddr::from(b);
            let port = client.read_u16().await?;
            (ip.to_string(), port)
        }
        _ => return Err(anyhow!("unsupported ATYP: {}", atyp)),
    };

    debug!("Request to {}:{} (cmd={})", addr, port, cmd);

    if cmd != 0x01 {
        // only support CONNECT
        send_reply(&mut client, 0x07).await?; // Command not supported
        return Err(anyhow!("unsupported command: {}", cmd));
    }

    // Whitelist check
    // If domain, resolve first
    let mut candidate_addrs = Vec::new();
    if let Ok(ip) = addr.parse::<IpAddr>() {
        // direct IP
        if !whitelist.allows_ip(&ip) {
            send_reply(&mut client, 0x02).await?; // Connection not allowed by rules
            return Err(anyhow!("ip not allowed: {}", ip));
        }
        candidate_addrs.push(SocketAddr::new(ip, port));
    } else {
        // domain
        if !whitelist.allows_domain(&addr) {
            send_reply(&mut client, 0x02).await?; // Connection not allowed
            return Err(anyhow!("domain not allowed: {}", addr));
        }

        // resolve domain to IPs
        let lookup = lookup_host((addr.as_str(), port)).await?;
        for sa in lookup {
            candidate_addrs.push(sa);
        }

        if candidate_addrs.is_empty() {
            send_reply(&mut client, 0x04).await?; // Host unreachable
            return Err(anyhow!("could not resolve: {}", addr));
        }
    }

    // Try connect to the first candidate address that succeeds
    let mut remote = None;
    for sa in candidate_addrs.iter() {
        match TcpStream::connect(sa).await {
            Ok(s) => {
                remote = Some(s);
                break;
            }
            Err(_) => continue,
        }
    }

    let mut remote = match remote {
        Some(s) => s,
        None => {
            send_reply(&mut client, 0x05).await?; // Connection refused
            return Err(anyhow!("failed to connect to target"));
        }
    };

    // success
    send_success_reply(&mut client).await?;

    // tunnel
    let (mut cr, mut cw) = client.split();
    let (mut rr, mut rw) = remote.split();

    let c2r = tokio::io::copy(&mut cr, &mut rw);
    let r2c = tokio::io::copy(&mut rr, &mut cw);

    let (res1, res2) = tokio::join!(c2r, r2c);
    debug!("copy results: {:?}, {:?}", res1, res2);

    Ok(())
}

async fn send_reply(stream: &mut TcpStream, rep: u8) -> Result<()> {
    // reply with ATYP=IPv4 and 0.0.0.0:0
    let buf = [SOCKS5_VER, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    stream.write_all(&buf).await?;
    Ok(())
}

async fn send_success_reply(stream: &mut TcpStream) -> Result<()> {
    // success, BND.ADDR 0.0.0.0:0
    send_reply(stream, 0x00).await
}
