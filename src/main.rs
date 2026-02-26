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
    let mut chat_history: Vec<PacketUpdate> = Vec::new();
    let mut list_state = ListState::default();
    let mut selected_stream: Option<String> = None;
    let mut searching = false;
    let mut search_query = String::new();
    let mut formatted_hex_view = String::from("Select a stream...");

    terminal.clear()?;

    loop {
        // --- 4. Handle Incoming Data ---
        while let Ok(update) = rx.try_recv() {
            let ip_pair = if let Some(pos) = update.summary.find(" [") {
                update.summary[..pos].to_string()
            } else {
                update.summary.clone()
            };

            let count = conversations.entry(ip_pair).or_insert(0);
            *count += 1;

            chat_history.push(update);
            if chat_history.len() > 50 {
                chat_history.remove(0);
            }
        }
        if let Some(ref target) = selected_stream {
        if let Some(last_pkt) = chat_history.iter().filter(|p| p.summary.contains(target)).last() {
             // Cache the formatted string here, once per update
             formatted_hex_view = format_hex(&last_pkt.raw_data);
        }
    }

        // --- 5. Draw UI (No Input Logic or 'break' allowed here) ---
terminal.draw(|f| {
    let size = f.size();
    
    // 1. Vertical Split: Main UI (top) and Search Bar (bottom)
    let v_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),
            Constraint::Length(if searching { 3 } else { 0 }),
        ])
        .split(size);

    // 2. Horizontal Split: Sidebar (left) and Right Column (right)
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(v_chunks[0]);

    // 3. Right Column Vertical Split: Feed (top) and Hex Inspector (bottom)
    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(60),
            Constraint::Percentage(40),
        ])
        .split(main_chunks[1]);

    // --- 4. Sidebar Logic & Rendering ---
    let mut streams: Vec<String> = conversations.keys()
        .filter(|s| s.to_lowercase().contains(&search_query.to_lowercase()))
        .cloned()
        .collect();
    streams.sort();

    if let Some(ref target) = selected_stream {
        if let Some(pos) = streams.iter().position(|s| s == target) {
            list_state.select(Some(pos));
        }
    }

    let sidebar_items: Vec<ListItem> = streams.iter().map(|s| {
        let count = conversations.get(s).unwrap_or(&0);
        ListItem::new(format!("[{}] {}", count, s)).style(Style::default().fg(Color::Cyan))
    }).collect();

    let sidebar = List::new(sidebar_items)
        .block(Block::default().title(" Streams ").borders(Borders::ALL))
        .highlight_style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow))
        .highlight_symbol(">> ");
    f.render_stateful_widget(sidebar, main_chunks[0], &mut list_state);

    // --- 5. Live Feed Logic & Rendering ---
    let filtered_lines: Vec<Line> = chat_history.iter()
        .filter(|pkt| {
            if let Some(ref target) = selected_stream {
                pkt.summary.contains(target)
            } else if !search_query.is_empty() {
                pkt.summary.to_lowercase().contains(&search_query.to_lowercase())
            } else {
                true
            }
        })
        .map(|pkt| {
            let s = &pkt.summary;
            let color = if s.contains("[HTTPS]") { Color::Magenta }
                else if s.contains("[DNS]") { Color::Blue }
                else if s.contains("[SSH]") { Color::Green }
                else { Color::Gray };

            let max_w = (right_chunks[0].width as usize).saturating_sub(4);
            let display_str = if s.len() > max_w {
                format!("{}...", &s[..max_w.saturating_sub(3)])
            } else {
                s.clone()
            };
            Line::from(Span::styled(display_str, Style::default().fg(color)))
        })
        .collect();

    let feed_title = format!(" Feed: {} ", selected_stream.as_deref().unwrap_or("All"));
    let feed = Paragraph::new(filtered_lines)
        .block(Block::default().title(feed_title).borders(Borders::ALL))
        .wrap(Wrap { trim: true });
    f.render_widget(feed, right_chunks[0]);

    // --- 6. Hex Inspector Logic & Rendering ---
    let inspector_content = if let Some(ref target) = selected_stream {
        chat_history.iter()
            .filter(|pkt| pkt.summary.contains(target))
            .last()
            .map(|pkt| format_hex(&pkt.raw_data))
            .unwrap_or_else(|| "Waiting for packet data...".to_string())
    } else {
        "Select a stream to inspect raw bytes...".to_string()
    };

    let inspector = Paragraph::new(formatted_hex_view.as_str())
            .block(Block::default().title(" Hex Inspector ").borders(Borders::ALL));
        f.render_widget(inspector, right_chunks[1]);

    // --- 7. Search Bar Rendering ---
    if searching {
        let s_bar = Paragraph::new(format!(" SEARCH: {}█", search_query))
            .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Yellow)));
        f.render_widget(s_bar, v_chunks[1]);
    }
})?;

        // --- 6. Handle Input (Safely outside the closure) ---
        if event::poll(Duration::from_millis(33))? {
            if let Event::Key(key) = event::read()? {
                let mut streams: Vec<String> = conversations.keys()
                    .filter(|s| s.to_lowercase().contains(&search_query.to_lowercase()))
                    .cloned()
                    .collect();
                streams.sort();

                if searching {
                    match key.code {
                        KeyCode::Enter => { searching = false; }
                        KeyCode::Esc => { 
                            searching = false; 
                            search_query.clear();
                            selected_stream = None;
                        }
                        KeyCode::Backspace => { search_query.pop(); }
                        KeyCode::Char(c) => { search_query.push(c); }
                        _ => {}
                    }
                } else {
                    match key.code {
                        KeyCode::Char('q') => {
                            let _ = child_process.kill();
                            break; // This works here!
                        }
                        KeyCode::Char('/') => {
                            searching = true;
                            search_query.clear();
                        }
                        KeyCode::Char('c') => {
                            conversations.clear();
                            chat_history.clear();
                            selected_stream = None;
                        }
                        KeyCode::Down => {
                            if !streams.is_empty() {
                                let i = match list_state.selected() {
                                    Some(i) => if i >= streams.len() - 1 { 0 } else { i + 1 },
                                    None => 0,
                                };
                                selected_stream = Some(streams[i].clone());
                                list_state.select(Some(i));
                            }
                        }
                        KeyCode::Up => {
                            if !streams.is_empty() {
                                let i = match list_state.selected() {
                                    Some(i) => if i == 0 { streams.len() - 1 } else { i - 1 },
                                    None => 0,
                                };
                                selected_stream = Some(streams[i].clone());
                                list_state.select(Some(i));
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    // --- 7. Cleanup ---
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    Ok(())
}

fn format_hex(data: &[u8]) -> String {
    let mut output = String::new();
    for chunk in data.chunks(16) {
        // Hex part
        for byte in chunk {
            output.push_str(&format!("{:02x} ", byte));
        }
        // Padding for short lines
        if chunk.len() < 16 {
            for _ in 0..(16 - chunk.len()) { output.push_str("   "); }
        }
        output.push_str(" | ");
        // ASCII part
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                output.push(Default::default()); // Placeholder for push
                output.pop();
                output.push(*byte as char);
            } else {
                output.push('.');
            }
        }
        output.push('\n');
    }
    output
}
