mod network;

use std::sync::mpsc;
use std::thread;

use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Terminal,
};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::io;

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    // 1. Create a channel for communication
    let (tx, rx) = mpsc::channel();
    let mut captured_messages: Vec<String> = Vec::new();

    // 2. Spawn the sniffer in the background
    tokio::spawn(async move {
        network::run_sniffer(tx).await;
    });
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut child = tokio::process::Command::new("dumpcap")
    .args(["-i", "wlan0", "-w", "-", "-F"]) // -P writes in pcap format to stdout
    .stdout(std::process::Stdio::piped())
    .spawn()?;

    let stdout = child.stdout.take().unwrap();
    // Now use a crate like 'pcap-parser' to read from this stream

    // App loop
    loop {
        // 3. Check for new packets without blocking the UI
        while let Ok(update) = rx.try_recv() {
            captured_messages.push(update.summary);
            if captured_messages.len() > 20 { // Keep memory low on the x220
                captured_messages.remove(0);
            }
        }

        terminal.draw(|f| {
            // Define Layout: Sidebar (25%) and Main Chat (75%)
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(25), Constraint::Percentage(75)])
                .split(f.size());

            // // 1. Sidebar: Active "Conversations" (IPs/Ports)
            // let streams = List::new(vec![
            //     ListItem::new("192.168.1.5 -> 8.8.8.8 (DNS)"),
            //     ListItem::new("10.0.0.2 -> 443 (HTTPS)"),
            // ])
            // .block(Block::default().title("Streams").borders(Borders::ALL));
            // f.render_widget(streams, chunks[0]);

            // // 2. Main: The Chat-like packet flow
            // let chat_content = "<- [SYN] 192.168.1.5\n   [SYN, ACK] -> 8.8.8.8\n<- [ACK] 192.168.1.5\n\n[GET /index.html] -- User-Agent: NixOS/Thinkpad";
            // let chat = Paragraph::new(chat_content)
            //     .block(Block::default().title("Conversation").borders(Borders::ALL));
            // f.render_widget(chat, chunks[1]);
        let display_text = captured_messages.join("\n");
            let chat = Paragraph::new(display_text)
                .block(Block::default().title("Live Traffic").borders(Borders::ALL));
            f.render_widget(chat, chunks[1]);
        })?;
        // })?;

        // Simple exit on 'q'
        if event::poll(std::time::Duration::from_millis(16))? {
            if let Event::Key(key) = event::read()? {
                if let KeyCode::Char('q') = key.code {
                    break;
                }
            }
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    Ok(())
}
