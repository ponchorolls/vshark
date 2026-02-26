use std::process::{Command, Stdio, Child};
use std::io::Read;
use std::sync::mpsc::Sender;
use etherparse::Ipv4Header;
use std::net::Ipv4Addr;

pub struct PacketUpdate {
    pub summary: String,
}

pub fn run_sniffer(tx: Sender<PacketUpdate>) -> Child {
    // We use the standard library Command here for easier pipe management
    let mut child = Command::new("/run/wrappers/bin/dumpcap")
        .args(["-i", "any", "-F", "pcap", "-n", "-q", "-w", "-"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null()) // Silence the promiscuous warning
        .spawn()
        .expect("Failed to spawn dumpcap");

    let mut stdout = child.stdout.take().expect("Failed to take stdout");

    // Move the heavy byte-scanning to a background thread
    tokio::task::spawn_blocking(move || {
        let mut buffer = Vec::new();
        let mut temp_buf = [0u8; 2048];
        loop {
            match stdout.read(&mut temp_buf) {
                Ok(0) => break, // Pipe closed
                Ok(n) => {
                    buffer.extend_from_slice(&temp_buf[..n]);
                    
                    // Prevent memory bloat on the x220
                    if buffer.len() > 5000 {
                        buffer.drain(..2000);
                    }

                    let mut i = 0;
                    while i < buffer.len().saturating_sub(20) {
                        // Look for IPv4 Magic Byte (0x45)
                        // Inside the while i < buffer.len() loop
                    if buffer[i] == 0x45 {
                        if let Ok((h, _)) = Ipv4Header::from_slice(&buffer[i..]) {
                            let src = Ipv4Addr::from(h.source);
                            let dst = Ipv4Addr::from(h.destination);
        
                            // Peek at the next 4 bytes for ports (TCP/UDP)
                            let mut protocol_tag = "";
                            let p_idx = i + 20; // Start of Transport Layer
                            if buffer.len() >= p_idx + 4 {
                                let dest_port = u16::from_be_bytes([buffer[p_idx + 2], buffer[p_idx + 3]]);
                                protocol_tag = match dest_port {
                                    443 => " [HTTPS]",
                                    80  => " [HTTP]",
                                    53  => " [DNS]",
                                    22  => " [SSH]",
                                    _   => "",
                                };
                            }

                            let _ = tx.send(PacketUpdate {
                                summary: format!("{} ➔ {}{}", src, dst, protocol_tag),
                            });
        
                            i += 20; 
                            continue;
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
