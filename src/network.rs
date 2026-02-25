use std::fs::File;
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::mpsc::Sender;
use pcap_parser::{LegacyPcapReader, PcapBlockOwned, traits::PcapReaderIterator};
use etherparse::{SlicedPacket, NetSlice, Ipv4Slice, Ipv6Slice};

pub struct PacketUpdate {
    pub summary: String,
}

pub async fn run_sniffer(tx: Sender<PacketUpdate>) {
    // 1. Start dumpcap writing to our FIFO
    // We use the wrapper, but tell it to write to a FILE instead of STDOUT
    let mut _child = Command::new("/run/wrappers/bin/dumpcap")
        .args([
            "-i", "any",
            "-F", "pcap",
            "-n",
            "-q",
            "-w", "/tmp/vshark_fifo" // Writing directly to the FIFO
        ])
        .stdout(Stdio::null()) 
        .spawn()
        .expect("Failed to start dumpcap");

    // 2. Open the FIFO for reading
    // This will block until dumpcap starts writing
    let mut file = File::open("/tmp/vshark_fifo").expect("Failed to open FIFO");
    
    let mut buffer = Vec::new();
    let mut temp_buf = [0u8; 1024];

    tokio::task::spawn_blocking(move || {
        loop {
            match file.read(&mut temp_buf) {
                Ok(0) => break,
                Ok(n) => {
                    buffer.extend_from_slice(&temp_buf[..n]);
                    let mut consumed_bytes = 0;

                    if let Ok(mut reader) = LegacyPcapReader::new(65536, &buffer[..]) {
                        while let Ok((offset, block)) = reader.next() {
                            consumed_bytes += offset;
                            if let PcapBlockOwned::Legacy(pkt) = block {
                                // SLL / IP detection logic
                                let net_slice = if let Ok(s) = SlicedPacket::from_ethernet(pkt.data) {
                                    s.net
                                } else if pkt.data.len() > 16 {
                                    match pkt.data[16] >> 4 {
                                        4 => Ipv4Slice::from_slice(&pkt.data[16..]).ok().map(NetSlice::Ipv4),
                                        6 => Ipv6Slice::from_slice(&pkt.data[16..]).ok().map(NetSlice::Ipv6),
                                        _ => None,
                                    }
                                } else { None };

                                if let Some(net) = net_slice {
                                    let summary = match net {
                                        NetSlice::Ipv4(h) => format!("{} ➔ {}", h.header().source_addr(), h.header().destination_addr()),
                                        NetSlice::Ipv6(h) => format!("{:?} ➔ {:?}", h.header().source_addr(), h.header().destination_addr()),
                                        _ => "Unknown".into(),
                                    };
                                    let _ = tx.send(PacketUpdate { summary });
                                }
                            }
                            reader.consume(offset);
                        }
                    }
                    if consumed_bytes > 0 {
                        buffer.drain(..consumed_bytes);
                    }
                }
                Err(_) => break,
            }
        }
    });
}
