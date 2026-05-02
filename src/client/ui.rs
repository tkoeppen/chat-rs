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
    /// Number of messages below the bottom of the visible window.
    /// `0` means pinned to the latest message; positive values mean the
    /// user has scrolled back into history.
    pub scroll: usize,
    /// Inner height of the room pane (excluding borders) as of the last
    /// render. Used by paging keys; updated by `render`.
    pub last_inner_h: usize,
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
            scroll: 0,
            last_inner_h: 0,
        }
    }

    pub fn push(&mut self, msg: DisplayMsg) {
        let was_capped = self.messages.len() == HISTORY_CAP;
        if was_capped {
            self.messages.pop_front();
        }
        self.messages.push_back(msg);
        // If the user is reading history, anchor their view to the same
        // historical position by incrementing scroll. (When the deque is
        // capped, len doesn't change so we don't need to bump.)
        if self.scroll > 0 && !was_capped {
            self.scroll += 1;
        }
        self.clamp_scroll();
    }

    pub fn push_system(&mut self, text: impl Into<String>) {
        self.push(DisplayMsg {
            ts_ms: now_ms(),
            kind: DisplayKind::System { text: text.into() },
        });
    }

    pub fn clear_messages(&mut self) {
        self.messages.clear();
        self.scroll = 0;
    }

    pub fn scroll_up(&mut self, n: usize) {
        self.scroll = self.scroll.saturating_add(n);
        self.clamp_scroll();
    }

    pub fn scroll_down(&mut self, n: usize) {
        self.scroll = self.scroll.saturating_sub(n);
    }

    pub fn scroll_to_latest(&mut self) {
        self.scroll = 0;
    }

    pub fn scroll_to_oldest(&mut self) {
        self.scroll = self.messages.len().saturating_sub(self.last_inner_h.max(1));
    }

    pub fn clamp_scroll(&mut self) {
        let max = self.messages.len().saturating_sub(self.last_inner_h.max(1));
        if self.scroll > max {
            self.scroll = max;
        }
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

pub fn render(f: &mut ratatui::Frame, state: &mut UiState) {
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
        " {} · {}  —  enter · /clear · ↑↓/PgUp/PgDn scroll · End live · ctrl-c quit",
        state.username, state.addr,
    ))
    .style(Style::default().fg(Color::Black).bg(Color::Cyan));
    f.render_widget(status, chunks[1]);

    let inner_h = chunks[2].height.saturating_sub(2) as usize;
    state.last_inner_h = inner_h;
    state.clamp_scroll();

    let len = state.messages.len();
    let end = len.saturating_sub(state.scroll);
    let start = end.saturating_sub(inner_h);
    let visible: Vec<ListItem> = state
        .messages
        .iter()
        .skip(start)
        .take(end - start)
        .map(|m| ListItem::new(format_line(m)))
        .collect();

    let title = if state.scroll > 0 {
        format!(" room (↑ scrolled {} — End to return) ", state.scroll)
    } else {
        " room ".to_string()
    };
    let messages = List::new(visible).block(Block::default().borders(Borders::ALL).title(title));
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
        KeyCode::Up => {
            state.scroll_up(1);
            KeyAction::None
        }
        KeyCode::Down => {
            state.scroll_down(1);
            KeyAction::None
        }
        KeyCode::PageUp => {
            let step = state.last_inner_h.saturating_sub(1).max(1);
            state.scroll_up(step);
            KeyAction::None
        }
        KeyCode::PageDown => {
            let step = state.last_inner_h.saturating_sub(1).max(1);
            state.scroll_down(step);
            KeyAction::None
        }
        KeyCode::Home => {
            state.scroll_to_oldest();
            KeyAction::None
        }
        KeyCode::End => {
            state.scroll_to_latest();
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

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> UiState {
        UiState::new(
            "alice".into(),
            Uuid::nil(),
            "127.0.0.1:3000".parse().unwrap(),
        )
    }

    fn sys(text: &str) -> DisplayMsg {
        DisplayMsg {
            ts_ms: 0,
            kind: DisplayKind::System { text: text.into() },
        }
    }

    #[test]
    fn push_keeps_scroll_zero_when_pinned() {
        let mut s = state();
        s.last_inner_h = 5;
        for i in 0..10 {
            s.push(sys(&format!("m{i}")));
        }
        assert_eq!(s.scroll, 0, "auto-scroll should keep view pinned to latest");
    }

    #[test]
    fn push_increments_scroll_when_scrolled() {
        let mut s = state();
        s.last_inner_h = 5;
        for i in 0..10 {
            s.push(sys(&format!("m{i}")));
        }
        s.scroll_up(3);
        assert_eq!(s.scroll, 3);
        s.push(sys("new"));
        assert_eq!(
            s.scroll, 4,
            "new msg while scrolled bumps scroll to anchor view"
        );
    }

    #[test]
    fn clear_messages_resets_scroll() {
        let mut s = state();
        s.last_inner_h = 5;
        for i in 0..20 {
            s.push(sys(&format!("m{i}")));
        }
        s.scroll_up(10);
        assert!(s.scroll > 0);
        s.clear_messages();
        assert_eq!(s.scroll, 0);
        assert!(s.messages.is_empty());
    }

    #[test]
    fn cap_evicts_oldest() {
        let mut s = state();
        for i in 0..(HISTORY_CAP + 5) {
            s.push(sys(&format!("m{i}")));
        }
        assert_eq!(s.messages.len(), HISTORY_CAP);
        let DisplayKind::System { text } = &s.messages.front().unwrap().kind else {
            panic!("expected System kind");
        };
        assert_eq!(text, "m5", "oldest 5 should have been evicted");
    }

    #[test]
    fn scroll_clamps_to_max() {
        let mut s = state();
        s.last_inner_h = 5;
        for i in 0..10 {
            s.push(sys(&format!("m{i}")));
        }
        s.scroll_up(100);
        // max scroll = len - inner_h = 10 - 5 = 5
        assert_eq!(s.scroll, 5);
    }
}
