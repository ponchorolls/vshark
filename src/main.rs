mod network;

use crate::network::PacketUpdate;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Terminal,
};
use std::{io, sync::mpsc, time::Duration};

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    // 1. Terminal Setup
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // 2. Communication Channel
    let (tx, rx) = mpsc::channel::<PacketUpdate>();

    // 3. Spawn the Sniffer (passing the sender)
    tokio::spawn(async move {
        network::run_sniffer(tx).await;
    });

    // 4. App State
    let mut chat_history: Vec<String> = Vec::new();

    // 5. Main UI Loop
loop {
    // 1. DRAIN the receiver - handle ALL pending packets
    let mut changed = false;
    while let Ok(update) = rx.try_recv() {
        chat_history.push(update.summary);
        if chat_history.len() > 30 { chat_history.remove(0); }
        changed = true;
    }

    // 2. ALWAYS draw if there's new data, otherwise draw on a timer
    terminal.draw(|f| {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0)])
            .split(f.size());

        let text = chat_history.join("\n");
        let p = Paragraph::new(text).block(Block::default().borders(Borders::ALL).title("Traffic"));
        f.render_widget(p, chunks[0]);
    })?;

    // 3. Short poll to keep the loop moving
    if event::poll(Duration::from_millis(5))? {
        if let Event::Key(key) = event::read()? {
            if let KeyCode::Char('q') = key.code { break; }
        }
    }
}

    // 7. Restoration
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    Ok(())
}
