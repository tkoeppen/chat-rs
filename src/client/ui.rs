//! Terminal UI for the chat client.
//!
//! Layout: 1-line status bar, scrolling messages pane, 3-line input box.
//! Auto-scrolls to the latest message; per-username color via a small palette.
//! Ctrl-C is captured as a key event (raw mode swallows the SIGINT) and
//! triggers a clean exit via `KeyAction::Quit`.

use std::collections::VecDeque;
use std::io::{Stdout, stdout};
use std::net::SocketAddr;

use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Position};
use ratatui::prelude::CrosstermBackend;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use uuid::Uuid;

use crate::crypto::room;
use crate::proto::{ClientFrame, MessageAd, RoomMessage, now_ms};

const HISTORY_CAP: usize = 500;

pub type Term = Terminal<CrosstermBackend<Stdout>>;

pub struct UiState {
    pub username: String,
    pub user_id: Uuid,
    pub addr: SocketAddr,
    pub input: String,
    pub messages: VecDeque<DisplayMsg>,
}

pub struct DisplayMsg {
    pub ts_ms: u64,
    pub kind: DisplayKind,
}

pub enum DisplayKind {
    Message { username: String, text: String },
    System { text: String },
}

pub enum KeyAction {
    None,
    Send(ClientFrame),
    Quit,
}

impl UiState {
    pub fn new(username: String, user_id: Uuid, addr: SocketAddr) -> Self {
        Self {
            username,
            user_id,
            addr,
            input: String::new(),
            messages: VecDeque::with_capacity(HISTORY_CAP),
        }
    }

    pub fn push(&mut self, msg: DisplayMsg) {
        if self.messages.len() == HISTORY_CAP {
            self.messages.pop_front();
        }
        self.messages.push_back(msg);
    }

    pub fn push_system(&mut self, text: impl Into<String>) {
        self.push(DisplayMsg {
            ts_ms: now_ms(),
            kind: DisplayKind::System { text: text.into() },
        });
    }
}

/// RAII guard: enters alt-screen + raw mode on construction, restores on drop.
/// Drop runs even on panic, so the user's terminal is never left scrambled.
pub struct TerminalGuard {
    terminal: Term,
}

impl TerminalGuard {
    pub fn enter() -> std::io::Result<Self> {
        enable_raw_mode()?;
        let mut out = stdout();
        execute!(out, EnterAlternateScreen)?;
        let terminal = Terminal::new(CrosstermBackend::new(out))?;
        Ok(Self { terminal })
    }

    pub fn term(&mut self) -> &mut Term {
        &mut self.terminal
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
        let _ = self.terminal.show_cursor();
    }
}

pub fn render(f: &mut ratatui::Frame, state: &UiState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // header
            Constraint::Length(1), // status
            Constraint::Min(1),    // messages
            Constraint::Length(3), // input
        ])
        .split(f.area());

    let header = Paragraph::new("Secure Terminal Chat")
        .alignment(Alignment::Center)
        .style(
            Style::default()
                .fg(Color::White)
                .bg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(header, chunks[0]);

    let status = Paragraph::new(format!(
        " {} · {}  —  enter to send · /clear · ctrl-c to quit",
        state.username, state.addr,
    ))
    .style(Style::default().fg(Color::Black).bg(Color::Cyan));
    f.render_widget(status, chunks[1]);

    let inner_h = chunks[2].height.saturating_sub(2) as usize;
    let visible: Vec<ListItem> = state
        .messages
        .iter()
        .rev()
        .take(inner_h)
        .rev()
        .map(|m| ListItem::new(format_line(m)))
        .collect();
    let messages = List::new(visible).block(Block::default().borders(Borders::ALL).title(" room "));
    f.render_widget(messages, chunks[2]);

    let input = Paragraph::new(state.input.as_str())
        .block(Block::default().borders(Borders::ALL).title(" message "));
    f.render_widget(input, chunks[3]);

    let cursor_x = chunks[3].x + 1 + state.input.chars().count() as u16;
    let cursor_y = chunks[3].y + 1;
    f.set_cursor_position(Position::new(cursor_x, cursor_y));
}

fn format_line(m: &DisplayMsg) -> Line<'_> {
    let ts = fmt_ts(m.ts_ms);
    match &m.kind {
        DisplayKind::Message { username, text } => Line::from(vec![
            Span::styled(format!("[{ts}] "), Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{username}: "),
                Style::default()
                    .fg(color_for(username))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(text.as_str()),
        ]),
        DisplayKind::System { text } => Line::from(vec![
            Span::styled(format!("[{ts}] "), Style::default().fg(Color::DarkGray)),
            Span::styled(
                text.as_str(),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::ITALIC),
            ),
        ]),
    }
}

fn fmt_ts(ms: u64) -> String {
    let secs = ms / 1000;
    let h = (secs / 3600) % 24;
    let m = (secs / 60) % 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

fn color_for(username: &str) -> Color {
    const PALETTE: &[Color] = &[
        Color::Cyan,
        Color::Green,
        Color::Magenta,
        Color::Yellow,
        Color::Blue,
        Color::LightCyan,
        Color::LightGreen,
        Color::LightMagenta,
        Color::LightYellow,
    ];
    let mut h: u32 = 0;
    for b in username.bytes() {
        h = h.wrapping_mul(31).wrapping_add(b as u32);
    }
    PALETTE[(h as usize) % PALETTE.len()]
}

pub fn handle_key(state: &mut UiState, key: KeyEvent, room_key: &[u8; 32]) -> KeyAction {
    if key.kind != KeyEventKind::Press {
        return KeyAction::None;
    }
    if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c')) {
        return KeyAction::Quit;
    }
    match key.code {
        KeyCode::Enter => {
            let line = std::mem::take(&mut state.input);
            let trimmed = line.trim_end();
            if trimmed.is_empty() {
                return KeyAction::None;
            }
            if trimmed == "/clear" {
                return KeyAction::Send(ClientFrame::Clear);
            }
            let ad = MessageAd {
                from: state.user_id,
                timestamp_ms: now_ms(),
            };
            match room::seal(room_key, trimmed.as_bytes(), &ad) {
                Ok(ct) => KeyAction::Send(ClientFrame::Message { ad, ciphertext: ct }),
                Err(_) => {
                    state.push_system("encryption failed");
                    KeyAction::None
                }
            }
        }
        KeyCode::Backspace => {
            state.input.pop();
            KeyAction::None
        }
        KeyCode::Char(c) => {
            state.input.push(c);
            KeyAction::None
        }
        _ => KeyAction::None,
    }
}

pub fn decrypt_to_display(room_key: &[u8; 32], m: &RoomMessage) -> DisplayMsg {
    match room::open(room_key, &m.ciphertext, &m.ad) {
        Ok(pt) => DisplayMsg {
            ts_ms: m.ad.timestamp_ms,
            kind: DisplayKind::Message {
                username: m.username.clone(),
                text: String::from_utf8_lossy(&pt).into_owned(),
            },
        },
        Err(_) => DisplayMsg {
            ts_ms: m.ad.timestamp_ms,
            kind: DisplayKind::System {
                text: format!("[decryption failed] {}", m.username),
            },
        },
    }
}
