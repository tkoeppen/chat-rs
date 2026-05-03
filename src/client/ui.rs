//! Terminal UI for the chat client.
//!
//! Layout: 1-line status bar, scrolling messages pane, 3-line input box.
//! Auto-scrolls to the latest message; per-username color via a small palette.
//! Ctrl-C is captured as a key event (raw mode swallows the SIGINT) and
//! triggers a clean exit via `KeyAction::Quit`.

use std::collections::{HashMap, VecDeque};
use std::io::{Stdout, stdout};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

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
use crate::proto::{
    ClientFrame, EPHEMERAL_MASK, EPHEMERAL_REVEAL_MS, EPHEMERAL_TTL_MS, MessageAd, RoomMessage,
    now_ms,
};

const HISTORY_CAP: usize = 500;

pub type Term = Terminal<CrosstermBackend<Stdout>>;

pub struct UiState {
    pub username: String,
    pub user_id: Uuid,
    pub addr: SocketAddr,
    pub room: String,
    pub input: String,
    pub messages: VecDeque<DisplayMsg>,
    /// Number of messages below the bottom of the visible window.
    /// `0` means pinned to the latest message; positive values mean the
    /// user has scrolled back into history.
    pub scroll: usize,
    /// Inner height of the room pane (excluding borders) as of the last
    /// render. Used by paging keys; updated by `render`.
    pub last_inner_h: usize,
    /// Next per-session counter we'll assign to an outgoing message. Bound
    /// into `MessageAd.counter` so peers (and the server) can reject replays.
    pub next_counter: u64,
    /// Highest counter we've accepted from each sender (keyed by `user_id`,
    /// which is fresh per session — collisions across sessions don't happen).
    pub seen_counters: HashMap<Uuid, u64>,
}

pub struct DisplayMsg {
    pub ts_ms: u64,
    pub kind: DisplayKind,
    /// Some(...) iff this is an ephemeral message (`/secret` or `/s`). Drives
    /// masking, Ctrl-R reveal, and `EPHEMERAL_TTL_MS` auto-expiry.
    pub ephemeral: Option<EphemeralState>,
}

pub struct EphemeralState {
    /// When the message arrived locally — drives the auto-expire deadline.
    pub received_at: Instant,
    /// `Some(t)` while currently revealed; cleared when `t` passes.
    pub revealed_until: Option<Instant>,
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
    pub fn new(username: String, user_id: Uuid, addr: SocketAddr, room: String) -> Self {
        Self {
            username,
            user_id,
            addr,
            room,
            input: String::new(),
            messages: VecDeque::with_capacity(HISTORY_CAP),
            scroll: 0,
            last_inner_h: 0,
            next_counter: 1,
            seen_counters: HashMap::new(),
        }
    }

    /// Returns true and updates the seen value if `counter` strictly exceeds
    /// the last accepted counter from `sender`; false otherwise (replay).
    pub fn try_accept_counter(&mut self, sender: Uuid, counter: u64) -> bool {
        let entry = self.seen_counters.entry(sender).or_insert(0);
        if counter > *entry {
            *entry = counter;
            true
        } else {
            false
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
            ephemeral: None,
        });
    }

    pub fn clear_messages(&mut self) {
        self.messages.clear();
        self.scroll = 0;
    }

    /// Drop ephemeral messages whose `received_at + EPHEMERAL_TTL_MS` has
    /// passed, and clear the reveal flag on any whose reveal window expired.
    /// Called from the event-loop tick.
    pub fn tick_expire_ephemerals(&mut self) {
        let now = Instant::now();
        let ttl = Duration::from_millis(EPHEMERAL_TTL_MS);
        let before = self.messages.len();
        self.messages.retain(|m| match &m.ephemeral {
            Some(e) => now.duration_since(e.received_at) < ttl,
            None => true,
        });
        // If we dropped messages while the user was scrolled back, keep the
        // historical anchor consistent with the smaller deque.
        if self.messages.len() < before {
            self.clamp_scroll();
        }
        // Re-mask any revealed messages whose reveal window expired.
        for m in &mut self.messages {
            if let Some(e) = &mut m.ephemeral
                && let Some(until) = e.revealed_until
                && now >= until
            {
                e.revealed_until = None;
            }
        }
    }

    /// Briefly reveal every currently-masked ephemeral message for the next
    /// `EPHEMERAL_REVEAL_MS`. Triggered by Ctrl-R.
    pub fn reveal_ephemerals(&mut self) {
        let until = Instant::now() + Duration::from_millis(EPHEMERAL_REVEAL_MS);
        for m in &mut self.messages {
            if let Some(e) = &mut m.ephemeral {
                e.revealed_until = Some(until);
            }
        }
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
        " {} · #{} · {}  —  enter · /(c)lear · /(q)uit · /(s)ecret <msg> · ^R reveal",
        state.username, state.room, state.addr,
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
        DisplayKind::Message { username, text } => {
            // Ephemeral + currently masked → render the fixed-length mask.
            // Revealed (Ctrl-R within the reveal window) → cleartext in italic
            // so the user knows it's transient.
            let now = Instant::now();
            let body = match &m.ephemeral {
                Some(e) if e.revealed_until.is_none_or(|t| now >= t) => {
                    Span::styled(EPHEMERAL_MASK, Style::default().fg(Color::DarkGray))
                }
                Some(_) => Span::styled(
                    text.as_str(),
                    Style::default()
                        .fg(Color::LightYellow)
                        .add_modifier(Modifier::ITALIC),
                ),
                None => Span::raw(text.as_str()),
            };
            // For ephemerals, append a `(Ns)` countdown to the username — gives
            // the reader a "how long do I have left to Ctrl-R" cue. The 500 ms
            // tick refreshes this between renders.
            let header = match &m.ephemeral {
                Some(e) => {
                    let secs_left = ephemeral_secs_left(e.received_at, now);
                    format!("{username} ({secs_left}): ")
                }
                None => format!("{username}: "),
            };
            Line::from(vec![
                Span::styled(format!("[{ts}] "), Style::default().fg(Color::DarkGray)),
                Span::styled(
                    header,
                    Style::default()
                        .fg(color_for(username))
                        .add_modifier(Modifier::BOLD),
                ),
                body,
            ])
        }
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

/// Whole seconds left before an ephemeral message hits its TTL. Saturates
/// at 0 so a tick that runs slightly after expiry never shows a negative.
fn ephemeral_secs_left(received_at: Instant, now: Instant) -> u64 {
    let elapsed_ms = now.duration_since(received_at).as_millis() as u64;
    EPHEMERAL_TTL_MS.saturating_sub(elapsed_ms).div_ceil(1000)
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
    // Ctrl-R: briefly reveal every currently-masked ephemeral message.
    if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('r')) {
        state.reveal_ephemerals();
        return KeyAction::None;
    }
    match key.code {
        KeyCode::Enter => {
            let line = std::mem::take(&mut state.input);
            let trimmed = line.trim_end();
            if trimmed.is_empty() {
                return KeyAction::None;
            }
            match trimmed {
                "/c" | "/clear" => return KeyAction::Send(ClientFrame::Clear),
                "/q" | "/quit" => return KeyAction::Quit,
                _ => {}
            }
            // /s <text> or /secret <text> → ephemeral message. Empty body
            // (just "/s" with nothing after) is a no-op.
            let (body, ephemeral) = if let Some(rest) = trimmed
                .strip_prefix("/s ")
                .or(trimmed.strip_prefix("/secret "))
            {
                let rest = rest.trim();
                if rest.is_empty() {
                    return KeyAction::None;
                }
                (rest.to_string(), true)
            } else {
                (trimmed.to_string(), false)
            };
            let counter = state.next_counter;
            state.next_counter = state.next_counter.saturating_add(1);
            let ad = MessageAd {
                from: state.user_id,
                username: state.username.clone(),
                counter,
                timestamp_ms: now_ms(),
                ephemeral,
            };
            match room::seal(room_key, body.as_bytes(), &ad) {
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
    let ephemeral = m.ad.ephemeral.then(|| EphemeralState {
        received_at: Instant::now(),
        revealed_until: None,
    });
    match room::open(room_key, &m.ciphertext, &m.ad) {
        Ok(pt) => DisplayMsg {
            ts_ms: m.ad.timestamp_ms,
            kind: DisplayKind::Message {
                username: m.username.clone(),
                text: String::from_utf8_lossy(&pt).into_owned(),
            },
            ephemeral,
        },
        Err(_) => DisplayMsg {
            ts_ms: m.ad.timestamp_ms,
            kind: DisplayKind::System {
                text: format!("[decryption failed] {}", m.username),
            },
            ephemeral: None,
        },
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    fn state() -> UiState {
        UiState::new(
            "alice".into(),
            Uuid::nil(),
            "127.0.0.1:3000".parse().unwrap(),
            "main".into(),
        )
    }

    fn sys(text: &str) -> DisplayMsg {
        DisplayMsg {
            ts_ms: 0,
            kind: DisplayKind::System { text: text.into() },
            ephemeral: None,
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

    fn submit(text: &str) -> KeyAction {
        let mut s = state();
        s.input = text.into();
        handle_key(
            &mut s,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &[0u8; 32],
        )
    }

    #[test]
    fn quit_aliases_exit() {
        for cmd in ["/q", "/quit"] {
            assert!(matches!(submit(cmd), KeyAction::Quit), "{cmd} should quit");
        }
    }

    #[test]
    fn clear_aliases_send_clear() {
        for cmd in ["/c", "/clear"] {
            assert!(
                matches!(submit(cmd), KeyAction::Send(ClientFrame::Clear)),
                "{cmd} should send Clear"
            );
        }
    }

    /// Client-side replay defense: a malicious server that re-injects an
    /// older `RoomMessage` should be ignored. Counters are tracked per
    /// `(sender_user_id)` and must strictly increase.
    #[test]
    fn try_accept_counter_rejects_replay_per_sender() {
        let mut s = state();
        let alice = Uuid::new_v4();
        let bob = Uuid::new_v4();
        assert!(s.try_accept_counter(alice, 1));
        assert!(s.try_accept_counter(alice, 2));
        assert!(!s.try_accept_counter(alice, 2), "exact replay rejected");
        assert!(!s.try_accept_counter(alice, 1), "out-of-order rejected");
        assert!(s.try_accept_counter(alice, 3), "monotone advance allowed");
        // Independent per sender — bob's counter is its own state.
        assert!(s.try_accept_counter(bob, 1));
    }

    fn ephemeral_msg(received_at: Instant) -> DisplayMsg {
        DisplayMsg {
            ts_ms: 0,
            kind: DisplayKind::Message {
                username: "alice".into(),
                text: "secret".into(),
            },
            ephemeral: Some(EphemeralState {
                received_at,
                revealed_until: None,
            }),
        }
    }

    /// `tick_expire_ephemerals` drops expired ephemeral messages and leaves
    /// non-ephemeral ones alone. Uses an artificially-aged `received_at` so
    /// the test doesn't have to actually sleep `EPHEMERAL_TTL_MS`.
    #[test]
    fn tick_expire_drops_aged_ephemerals_only() {
        let mut s = state();
        let aged = Instant::now() - Duration::from_millis(EPHEMERAL_TTL_MS + 100);
        let fresh = Instant::now();
        s.push(ephemeral_msg(aged));
        s.push(ephemeral_msg(fresh));
        s.push(sys("regular system msg"));
        s.tick_expire_ephemerals();
        assert_eq!(
            s.messages.len(),
            2,
            "aged ephemeral dropped; fresh + system kept"
        );
    }

    /// `ephemeral_secs_left` rounds up so the on-screen counter shows
    /// `(30) → (29) → … → (1)` over the message's lifetime, never `(0)`
    /// while the message still exists.
    #[test]
    fn ephemeral_countdown_rounds_up() {
        let now = Instant::now();
        // Just-arrived: full TTL.
        assert_eq!(ephemeral_secs_left(now, now), EPHEMERAL_TTL_MS / 1000);
        // 1 ms in: still 30 (ceil leaves the second intact until elapsed crosses 1 s).
        let one_ms_later = now + Duration::from_millis(1);
        assert_eq!(
            ephemeral_secs_left(now, one_ms_later),
            EPHEMERAL_TTL_MS / 1000
        );
        // Exactly 1 s in: counter ticks down by one.
        let one_s_later = now + Duration::from_secs(1);
        assert_eq!(
            ephemeral_secs_left(now, one_s_later),
            EPHEMERAL_TTL_MS / 1000 - 1
        );
        // 1 ms before TTL: still showing 1.
        let almost_done = now + Duration::from_millis(EPHEMERAL_TTL_MS - 1);
        assert_eq!(ephemeral_secs_left(now, almost_done), 1);
        // Past TTL: saturates to 0 (tick_expire would have dropped the message
        // by the time the renderer sees this state).
        let after_ttl = now + Duration::from_millis(EPHEMERAL_TTL_MS + 500);
        assert_eq!(ephemeral_secs_left(now, after_ttl), 0);
    }

    /// `reveal_ephemerals` flips the reveal flag on, and `tick_expire`
    /// flips it back off once the reveal window passes.
    #[test]
    fn reveal_then_remask_after_window() {
        let mut s = state();
        s.push(ephemeral_msg(Instant::now()));
        s.reveal_ephemerals();
        let revealed = matches!(
            &s.messages[0].ephemeral,
            Some(e) if e.revealed_until.is_some(),
        );
        assert!(revealed, "reveal_ephemerals must set revealed_until");

        // Force the reveal window into the past, then tick.
        if let Some(e) = &mut s.messages[0].ephemeral {
            e.revealed_until = Some(Instant::now() - Duration::from_millis(1));
        }
        s.tick_expire_ephemerals();
        let still_revealed = matches!(
            &s.messages[0].ephemeral,
            Some(e) if e.revealed_until.is_some(),
        );
        assert!(!still_revealed, "tick must clear an expired reveal flag");
    }
}
