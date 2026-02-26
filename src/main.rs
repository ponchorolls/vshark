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
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Terminal,
};
use std::{collections::HashMap, io, sync::mpsc, time::Duration};

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    // 1. Setup Terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // 2. Setup Communication & Sniffer
    let (tx, rx) = mpsc::channel::<PacketUpdate>();
    let mut child_process = network::run_sniffer(tx);

    // 3. App State
    let mut conversations: HashMap<String, u64> = HashMap::new();
    let mut chat_history: Vec<String> = Vec::new();
    let mut list_state = ListState::default();
    let mut selected_stream: Option<String> = None;

    terminal.clear()?;

    loop {
        // --- 4. Handle Incoming Data ---
        while let Ok(update) = rx.try_recv() {
            // We use the base IP pair as the key for the sidebar
            let ip_pair = if let Some(pos) = update.summary.find(" [") {
                update.summary[..pos].to_string()
            } else {
                update.summary.clone()
            };

            let count = conversations.entry(ip_pair).or_insert(0);
            *count += 1;

            chat_history.push(update.summary);
            if chat_history.len() > 100 {
                chat_history.remove(0);
            }
        }

        // --- 5. Draw UI ---
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
                .split(f.size());

            // Get and Sort Streams for Sidebar
            let mut streams: Vec<String> = conversations.keys().cloned().collect();
            streams.sort(); // Keeps selection stable

            // Sync the selection index to the ID (the IP string)
            if let Some(ref target) = selected_stream {
                if let Some(new_index) = streams.iter().position(|s| s == target) {
                    list_state.select(Some(new_index));
                }
            } else if !streams.is_empty() && list_state.selected().is_none() {
                list_state.select(Some(0));
                selected_stream = Some(streams[0].clone());
            }

            // Sidebar Rendering
            let sidebar_items: Vec<ListItem> = streams
                .iter()
                .map(|s| {
                    let count = conversations.get(s).unwrap_or(&0);
                    ListItem::new(format!("[{}] {}", count, s)).style(Style::default().fg(Color::Cyan))
                })
                .collect();

            let sidebar = List::new(sidebar_items)
                .block(Block::default().title(" Streams ").borders(Borders::ALL))
                .highlight_style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow))
                .highlight_symbol(">> ");
            f.render_stateful_widget(sidebar, chunks[0], &mut list_state);

            // Live Feed Rendering with Protocol Colors
            let filtered_lines: Vec<Line> = chat_history
                .iter()
                .filter(|msg| {
                    if let Some(ref target) = selected_stream {
                        msg.contains(target)
                    } else {
                        true
                    }
                })
                .map(|s| {
                    let color = if s.contains("[HTTPS]") { Color::Magenta }
                        else if s.contains("[DNS]") { Color::Blue }
                        else if s.contains("[SSH]") { Color::Green }
                        else if s.contains("[HTTP]") { Color::Yellow }
                        else { Color::Gray };

                    // Manual truncation for the x220 screen
                    let max_w = (chunks[1].width as usize).saturating_sub(4);
                    let display_str = if s.len() > max_w {
                        format!("{}...", &s[..max_w.saturating_sub(3)])
                    } else {
                        s.clone()
                    };

                    Line::from(Span::styled(display_str, Style::default().fg(color)))
                })
                .collect();

            let chat_title = format!(" Feed: {} ", selected_stream.as_deref().unwrap_or("All"));
            let chat = Paragraph::new(filtered_lines)
                .block(Block::default().title(chat_title).borders(Borders::ALL))
                .wrap(Wrap { trim: true });
            f.render_widget(chat, chunks[1]);
        })?;

        // --- 6. Handle Input ---
        if event::poll(Duration::from_millis(16))? {
            if let Event::Key(key) = event::read()? {
                let mut streams: Vec<String> = conversations.keys().cloned().collect();
                streams.sort();

                match key.code {
                    KeyCode::Char('q') => {
                        let _ = child_process.kill();
                        break;
                    }
                    KeyCode::Down => {
                        if !streams.is_empty() {
                            let i = match list_state.selected() {
                                Some(i) => if i >= streams.len() - 1 { 0 } else { i + 1 },
                                None => 0,
                            };
                            selected_stream = Some(streams[i].clone());
                        }
                    }
                    KeyCode::Up => {
                        if !streams.is_empty() {
                            let i = match list_state.selected() {
                                Some(i) => if i == 0 { streams.len() - 1 } else { i - 1 },
                                None => 0,
                            };
                            selected_stream = Some(streams[i].clone());
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // --- 7. Cleanup ---
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    Ok(())
}
