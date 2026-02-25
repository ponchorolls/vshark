use std::process::Stdio;
use tokio::io::{AsyncReadExt, BufReader};
use tokio::process::Command;
use std::sync::mpsc::Sender;

pub struct PacketUpdate {
    pub summary: String,
}

pub async fn run_sniffer(tx: Sender<PacketUpdate>) {
    // -i any: listen on all interfaces
    // -w -: output raw pcap to stdout
    // -q: be quiet (no status messages)
    let mut child = Command::new("dumpcap")
        .args(["-i", "any", "-w", "-", "-q"])
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to start dumpcap. Is it in your NixOS config?");

    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let mut buffer = [0u8; 4096];

    loop {
        match reader.read(&mut buffer).await {
            Ok(n) if n > 0 => {
                // For now, we'll just send a "Packet Received" signal.
                // Later, we'll use 'pcap-parser' here to extract IPs/Protocols.
                let _ = tx.send(PacketUpdate {
                    summary: format!("Captured {} bytes", n),
                });
            }
            Ok(_) => break, // Stream ended
            Err(_) => break,
        }
    }
}