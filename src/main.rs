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
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Terminal,
    };
use std::{collections::HashMap, io, sync::mpsc, time::Duration};

// ... existing imports ...

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // 1. Create the channel first
    let (tx, rx) = mpsc::channel::<PacketUpdate>();

    // 2. Start the sniffer ONCE. 
    // It returns the child process handle and spawns its own thread.
    let mut child_process = network::run_sniffer(tx); 

    let mut conversations: HashMap<String, u64> = HashMap::new();
    let mut chat_history: Vec<String> = Vec::new();
    let mut list_state = ListState::default();
    list_state.select(Some(0));

    terminal.clear()?;
    loop {
        while let Ok(update) = rx.try_recv() {
            let count = conversations.entry(update.summary.clone()).or_insert(0);
            *count += 1;

            // Manual truncation to prevent border overflow
            let max_w = (terminal.size()?.width as usize * 7 / 10).saturating_sub(4);
            let mut clean_summary = update.summary.clone();
            if clean_summary.len() > max_w {
                clean_summary.truncate(max_w - 3);
                clean_summary.push_str("...");
            }

            chat_history.push(clean_summary);
            if chat_history.len() > 50 { chat_history.remove(0); }
        }

        terminal.draw(|f| {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(f.size());

    // Prepare sorted list for sidebar
    let mut streams: Vec<String> = conversations.keys().cloned().collect();
    streams.sort(); // Consistent ordering is key for selection stability

    // Get the focused IP pair based on selection
    let focused_ip = list_state.selected().and_then(|i| streams.get(i));

    // 1. Sidebar with Highlight
    let items: Vec<ListItem> = streams.iter().map(|s| {
        ListItem::new(s.as_str()).style(ratatui::style::Style::default().fg(ratatui::style::Color::Cyan))
    }).collect();

    let sidebar = List::new(items)
        .block(Block::default().title(" Streams ").borders(Borders::ALL))
        .highlight_style(ratatui::style::Style::default().add_modifier(ratatui::style::Modifier::BOLD).fg(ratatui::style::Color::Yellow))
        .highlight_symbol(">> ");
    
    f.render_stateful_widget(sidebar, chunks[0], &mut list_state);

    // 2. Filtered Live Feed
    let filtered_content: Vec<String> = chat_history.iter()
        .filter(|msg| {
            if let Some(target) = focused_ip {
                msg.contains(target) // Only show packets matching the selected stream
            } else {
                true // Show everything if nothing is selected
            }
        })
        .map(|s| {
            // Your existing truncation logic
            let max_w = (chunks[1].width as usize).saturating_sub(4);
            if s.len() > max_w { format!("{}...", &s[..max_w - 3]) } else { s.clone() }
        })
        .collect();

let styled_content: Vec<ratatui::text::Line> = filtered_content.iter()
    .map(|s| {
        let color = if s.contains("[HTTPS]") {
            ratatui::style::Color::Magenta
        } else if s.contains("[DNS]") {
            ratatui::style::Color::Blue
        } else if s.contains("[SSH]") {
            ratatui::style::Color::Green
        } else if s.contains("[HTTP]") {
            ratatui::style::Color::Yellow
        } else {
            ratatui::style::Color::Gray
        };

        ratatui::text::Line::from(ratatui::text::Span::styled(
            s.clone(),
            ratatui::style::Style::default().fg(color)
        ))
    })
    .collect();

let chat = Paragraph::new(styled_content)
    .block(Block::default().title(" Protocol Feed ").borders(Borders::ALL))
    .wrap(ratatui::widgets::Wrap { trim: true });
    
    f.render_widget(chat, chunks[1]);
})?;

if event::poll(Duration::from_millis(16))? {
    if let Event::Key(key) = event::read()? {
        match key.code {
            KeyCode::Char('q') => {
                let _ = child_process.kill();
                break;
            }
            KeyCode::Down => {
                let i = match list_state.selected() {
                    Some(i) => if i >= conversations.len().saturating_sub(1) { 0 } else { i + 1 },
                    None => 0,
                };
                list_state.select(Some(i));
            }
            KeyCode::Up => {
                let i = match list_state.selected() {
                    Some(i) => if i == 0 { conversations.len().saturating_sub(1) } else { i - 1 },
                    None => 0,
                };
                list_state.select(Some(i));
            }
            _ => {}
        }
    }
}
    }

    // ... cleanup code ...
    Ok(())
}
