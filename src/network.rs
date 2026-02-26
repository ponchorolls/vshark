use std::process::{Command, Stdio, Child};
use std::io::Read;
use std::sync::mpsc::Sender;
use etherparse::Ipv4Header;
use std::net::Ipv4Addr;

pub struct PacketUpdate {
    pub summary: String,
    pub raw_data: Vec<u8>, // New: Holds the actual packet bytes
}

pub fn run_sniffer(tx: Sender<PacketUpdate>) -> Child {
    let mut child = Command::new("/run/wrappers/bin/dumpcap")
        .args(["-i", "any", "-F", "pcap", "-n", "-q", "-w", "-"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to spawn dumpcap");

    let mut stdout = child.stdout.take().expect("Failed to take stdout");

    tokio::task::spawn_blocking(move || {
        let mut buffer = Vec::new();
        let mut temp_buf = [0u8; 2048];
        loop {
            match stdout.read(&mut temp_buf) {
                Ok(0) => break,
                Ok(n) => {
                    buffer.extend_from_slice(&temp_buf[..n]);
                    if buffer.len() > 10000 { buffer.drain(..5000); }

                    let mut i = 0;
                    while i < buffer.len().saturating_sub(20) {
                        if buffer[i] == 0x45 {
                            if let Ok((h, _)) = Ipv4Header::from_slice(&buffer[i..]) {
                                let total_len = h.total_len as usize;
                                
                                // Ensure we have the full packet in the buffer
                                if buffer.len() >= i + total_len {
                                    let raw_packet = buffer[i..i + total_len].to_vec();
                                    let src = Ipv4Addr::from(h.source);
                                    let dst = Ipv4Addr::from(h.destination);
                                    
                                    // Detect Port for protocol tag
                                    let mut tag = String::new();
                                    if raw_packet.len() >= 24 {
                                        let d_port = u16::from_be_bytes([raw_packet[22], raw_packet[23]]);
                                        tag = match d_port {
                                            443 => " [HTTPS]".to_string(),
                                            53 =>  " [DNS]".to_string(),
                                            22 =>  " [SSH]".to_string(),
                                            67 =>  " [DHCP Server]".to_string(),
                                            68 =>  " [DHCP Client]".to_string(),
                                            _ => "".to_string(),
                                        };
                                    }

                                    let _ = tx.send(PacketUpdate {
                                        summary: format!("{} ➔ {}{}", src, dst, tag),
                                        raw_data: raw_packet,
                                    });
                                    
                                    i += total_len;
                                    continue;
                                }
                            }
                        }
                        i += 1;
                    }
                }
                Err(_) => break,
            }
        }
    });

    child
}
