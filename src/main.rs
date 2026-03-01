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
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Sparkline, Wrap},
    Terminal,
};
use std::{collections::HashMap, io, sync::mpsc, time::{Duration, Instant}};

// Helper: Formats raw bytes into a "Hex + ASCII" view
fn format_hex(data: &[u8]) -> String {
    let mut output = String::new();
    for chunk in data.chunks(16) {
        for byte in chunk {
            output.push_str(&format!("{:02x} ", byte));
        }
        if chunk.len() < 16 {
            for _ in 0..(16 - chunk.len()) { output.push_str("   "); }
        }
        output.push_str(" | ");
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                output.push(*byte as char);
            } else {
                output.push('.');
            }
        }
        output.push('\n');
    }
    output
}

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    // 1. Terminal Setup
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // 2. State & Communication
    let (tx, rx) = mpsc::channel::<PacketUpdate>();
    let mut child_process = network::run_sniffer(tx);

    let mut conversations: HashMap<String, u64> = HashMap::new();
    let mut chat_history: Vec<PacketUpdate> = Vec::new();
    let mut list_state = ListState::default();
    let mut selected_stream: Option<String> = None;
    let mut searching = false;
    let mut search_query = String::new();
    
    // Sparkline state
    let mut sparkline_data: Vec<u64> = vec![0; 100];
    let mut packets_this_tick: u64 = 0;
    let mut last_tick = Instant::now();
    let mut formatted_hex_view = String::from("Select a stream to inspect...");

    terminal.clear()?;

    loop {
        // 3. Process Incoming Packets
        while let Ok(update) = rx.try_recv() {
            let ip_pair = if let Some(pos) = update.summary.find(" [") {
                update.summary[..pos].to_string()
            } else {
                update.summary.clone()
            };

            let count = conversations.entry(ip_pair).or_insert(0);
            *count += 1;
            packets_this_tick += 1;

            chat_history.push(update);
            if chat_history.len() > 50 { chat_history.remove(0); }
        }

        // 4. Update Sparkline and Hex Cache
        if last_tick.elapsed() >= Duration::from_millis(200) {
            sparkline_data.push(packets_this_tick);
            if sparkline_data.len() > 100 { sparkline_data.remove(0); }
            packets_this_tick = 0;
            last_tick = Instant::now();
            
            // Update Hex view only when data or selection might have changed
            if let Some(ref target) = selected_stream {
                if let Some(last_pkt) = chat_history.iter().filter(|p| p.summary.contains(target)).last() {
                    formatted_hex_view = format_hex(&last_pkt.raw_data);
                }
            }
        }

        // 5. Drawing
        terminal.draw(|f| {
            let size = f.size();
            let main_v = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(3), Constraint::Length(if searching { 3 } else { 0 })])
                .split(size);

            let main_h = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
                .split(main_v[0]);

            let right_v = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(35), Constraint::Length(3)])
                .split(main_h[1]);

            // Sidebar
            let mut streams: Vec<String> = conversations.keys()
                .filter(|s| s.to_lowercase().contains(&search_query.to_lowercase()))
                .cloned().collect();
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
            f.render_stateful_widget(sidebar, main_h[0], &mut list_state);

            // Feed
            let feed_lines: Vec<Line> = chat_history.iter()
                .filter(|pkt| {
                    if let Some(ref t) = selected_stream { pkt.summary.contains(t) }
                    else { pkt.summary.to_lowercase().contains(&search_query.to_lowercase()) }
                })
                .map(|pkt| {
                    let color = if pkt.summary.contains("[HTTPS]") { Color::Magenta }
                        else if pkt.summary.contains("[DNS]") { Color::Blue }
                        else if pkt.summary.contains("[SSH]") { Color::Green }
                        else { Color::Gray };
                    Line::from(Span::styled(&pkt.summary, Style::default().fg(color)))
                }).collect();

            f.render_widget(Paragraph::new(feed_lines).block(Block::default().title(" Feed ").borders(Borders::ALL)).wrap(Wrap { trim: true }), right_v[0]);

            // Inspector
            f.render_widget(Paragraph::new(formatted_hex_view.as_str()).block(Block::default().title(" Hex Inspector ").borders(Borders::ALL)).style(Style::default().fg(Color::DarkGray)), right_v[1]);

            // Sparkline
            f.render_widget(Sparkline::default().block(Block::default().title(" Activity ").borders(Borders::LEFT | Borders::RIGHT | Borders::BOTTOM)).data(&sparkline_data).style(Style::default().fg(Color::Green)), right_v[2]);

            // Search Bar
            if searching {
                f.render_widget(Paragraph::new(format!(" SEARCH: {}█", search_query)).block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Yellow))), main_v[1]);
            }
        })?;

        // 6. Input Handling
        if event::poll(Duration::from_millis(10))? {
            if let Event::Key(key) = event::read()? {
                let mut streams: Vec<String> = conversations.keys()
                    .filter(|s| s.to_lowercase().contains(&search_query.to_lowercase()))
                    .cloned().collect();
                streams.sort();

                if searching {
                    match key.code {
                        KeyCode::Enter => searching = false,
                        KeyCode::Esc => { searching = false; search_query.clear(); selected_stream = None; }
                        KeyCode::Backspace => { search_query.pop(); }
                        KeyCode::Char(c) => search_query.push(c),
                        _ => {}
                    }
                } else {
                    match key.code {
                        KeyCode::Char('q') => { let _ = child_process.kill(); break; }
                        KeyCode::Char('/') => { searching = true; search_query.clear(); }
                        KeyCode::Char('c') => { conversations.clear(); chat_history.clear(); selected_stream = None; }
                        KeyCode::Down => if !streams.is_empty() {
                            let i = match list_state.selected() { Some(i) => if i >= streams.len() - 1 { 0 } else { i + 1 }, None => 0 };
                            selected_stream = Some(streams[i].clone());
                        }
                        KeyCode::Up => if !streams.is_empty() {
                            let i = match list_state.selected() { Some(i) => if i == 0 { streams.len() - 1 } else { i - 1 }, None => 0 };
                            selected_stream = Some(streams[i].clone());
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    Ok(())
}
