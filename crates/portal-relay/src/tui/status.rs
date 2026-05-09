//! Read-only R15 v0.1 relay status TUI view.

use std::fmt::Display;
use std::time::Duration;

use ratatui::backend::Backend;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Text};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::{Frame, Terminal};
use thiserror::Error;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::admin::View;

/// Lifecycle value rendered by the status TUI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lifecycle {
    /// Relay is stopped.
    Stopped,
    /// Relay is running.
    Running {
        /// Duration since the relay entered the running state.
        uptime: Duration,
    },
    /// Relay is draining after shutdown was requested.
    Stopping,
    /// Relay observed an operator-visible error.
    Errored(String),
}

impl Lifecycle {
    const fn label(&self) -> &str {
        match self {
            Self::Stopped => "Stopped",
            Self::Running { .. } => "Running",
            Self::Stopping => "Stopping",
            Self::Errored(_) => "Errored",
        }
    }
}

/// Recent operator-visible status event rendered by the status TUI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecentEvent {
    /// Error surfaced to an operator.
    Error(String),
    /// Policy or identity denial surfaced to an operator.
    Denial(String),
    /// Throttle/rate-limit event surfaced to an operator.
    Throttle(String),
}

impl RecentEvent {
    fn line(&self) -> String {
        match self {
            Self::Error(message) => format!("error: {message}"),
            Self::Denial(message) => format!("denial: {message}"),
            Self::Throttle(message) => format!("throttle: {message}"),
        }
    }
}

/// Operator-facing identity health summary rendered alongside leases.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IdentityHealth {
    /// Approved identities.
    pub approved: usize,
    /// Identities awaiting approval.
    pub pending: usize,
    /// Denied identities.
    pub denied: usize,
    /// Banned identities.
    pub banned: usize,
}

/// Aggregate bytes-per-second values rendered by the status TUI.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BpsAggregate {
    /// Inbound bytes per second.
    pub inbound: u64,
    /// Outbound bytes per second.
    pub outbound: u64,
}

impl BpsAggregate {
    /// Combined inbound + outbound bytes per second.
    #[must_use]
    pub const fn total(self) -> u64 {
        self.inbound.saturating_add(self.outbound)
    }
}

/// Minimal status snapshot consumed by the R15 v0.1 TUI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusSnapshot {
    /// Current lifecycle state.
    pub lifecycle: Lifecycle,
    /// Recent operator-visible events, newest-last.
    pub recent_events: Vec<RecentEvent>,
    /// Active lease count.
    pub lease_count: usize,
    /// Operator-facing identity health summary.
    pub identity_health: IdentityHealth,
    /// Aggregate bytes-per-second counters.
    pub bps: BpsAggregate,
}

impl Default for StatusSnapshot {
    fn default() -> Self {
        Self {
            lifecycle: Lifecycle::Stopped,
            recent_events: Vec::new(),
            lease_count: 0,
            identity_health: IdentityHealth::default(),
            bps: BpsAggregate::default(),
        }
    }
}

/// Errors returned by the status TUI loop.
#[derive(Debug, Error)]
pub enum TuiError {
    /// Ratatui backend failed while drawing.
    #[error("tui draw failed: {0}")]
    Draw(String),
}

/// Read-only status view for relay lifecycle, recent events, leases/identity health, and BPS.
#[derive(Debug, Clone, Copy, Default)]
pub struct StatusView;

impl StatusView {
    /// Construct a status view renderer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    fn lifecycle_text(snapshot: &StatusSnapshot) -> Text<'_> {
        let mut lines = vec![Line::from(format!("state: {}", snapshot.lifecycle.label()))];
        match &snapshot.lifecycle {
            Lifecycle::Running { uptime } => {
                lines.push(Line::from(format!("uptime: {}", format_uptime(*uptime))));
            }
            Lifecycle::Errored(message) => {
                lines.push(Line::from(format!("error: {message}")));
            }
            Lifecycle::Stopped | Lifecycle::Stopping => {}
        }
        Text::from(lines)
    }

    fn recent_events_text(snapshot: &StatusSnapshot) -> Text<'_> {
        if snapshot.recent_events.is_empty() {
            return Text::from("none");
        }

        Text::from(
            snapshot
                .recent_events
                .iter()
                .map(|event| Line::from(event.line()))
                .collect::<Vec<_>>(),
        )
    }

    fn leases_identity_text(snapshot: &StatusSnapshot) -> Text<'_> {
        Text::from(vec![
            Line::from(format!("leases active: {}", snapshot.lease_count)),
            Line::from(format!(
                "identity approved: {}",
                snapshot.identity_health.approved
            )),
            Line::from(format!(
                "identity pending: {}",
                snapshot.identity_health.pending
            )),
            Line::from(format!(
                "identity denied: {}",
                snapshot.identity_health.denied
            )),
            Line::from(format!(
                "identity banned: {}",
                snapshot.identity_health.banned
            )),
        ])
    }

    fn bps_text(snapshot: &StatusSnapshot) -> Text<'_> {
        Text::from(vec![
            Line::from(format!("in: {} B/s", snapshot.bps.inbound)),
            Line::from(format!("out: {} B/s", snapshot.bps.outbound)),
            Line::from(format!("total: {} B/s", snapshot.bps.total())),
        ])
    }
}

impl View<StatusSnapshot> for StatusView {
    fn render(&self, frame: &mut Frame<'_>, area: Rect, snapshot: &StatusSnapshot) {
        let panes = Layout::horizontal([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(area);

        frame.render_widget(
            Paragraph::new(Self::lifecycle_text(snapshot))
                .block(Block::new().title("Lifecycle").borders(Borders::ALL)),
            panes[0],
        );
        frame.render_widget(
            Paragraph::new(Self::recent_events_text(snapshot))
                .block(Block::new().title("Recent Events").borders(Borders::ALL))
                .style(Style::new().red()),
            panes[1],
        );
        frame.render_widget(
            Paragraph::new(Self::leases_identity_text(snapshot)).block(
                Block::new()
                    .title("Leases / Identity")
                    .borders(Borders::ALL),
            ),
            panes[2],
        );
        frame.render_widget(
            Paragraph::new(Self::bps_text(snapshot))
                .block(Block::new().title("BPS").borders(Borders::ALL)),
            panes[3],
        );
    }
}

fn format_uptime(uptime: Duration) -> String {
    let seconds = uptime.as_secs();
    let hours = seconds / 3_600;
    let minutes = (seconds % 3_600) / 60;
    let seconds = seconds % 60;
    format!("{hours}h {minutes:02}m {seconds:02}s")
}

/// Run the status loop backed by a crossterm terminal.
///
/// Enables raw mode, enters the alternate screen, and renders the
/// [`StatusView`] on every `snapshot_rx.changed()` tick.  Exits cleanly on
/// `cancel.cancelled()`, `q` / `Q`, or `Ctrl-C`.
///
/// # Errors
///
/// Returns [`TuiError::Draw`] if the terminal backend fails while drawing.
#[expect(
    clippy::too_many_lines,
    reason = "terminal lifecycle is sequential by nature; splitting would obscure the setup→loop→teardown flow"
)]
pub async fn run(
    mut snapshot_rx: watch::Receiver<StatusSnapshot>,
    cancel: CancellationToken,
) -> Result<(), TuiError> {
    use std::io::stdout;
    use std::time::Duration;

    use ratatui_crossterm::crossterm::event;
    use ratatui_crossterm::crossterm::terminal::{
        disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
    };
    use ratatui_crossterm::crossterm::execute;
    use ratatui_crossterm::CrosstermBackend;

    // -- Terminal setup -------------------------------------------------------

    if let Err(e) = enable_raw_mode() {
        return Err(TuiError::Draw(e.to_string()));
    }

    let mut stdout = stdout();
    if let Err(e) = execute!(
        stdout,
        EnterAlternateScreen,
        event::EnableMouseCapture,
    ) {
        let _ = disable_raw_mode();
        return Err(TuiError::Draw(e.to_string()));
    }

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = match Terminal::new(backend) {
        Ok(t) => t,
        Err(e) => {
            let _ = execute!(
                std::io::stdout(),
                LeaveAlternateScreen,
                event::DisableMouseCapture
            );
            let _ = disable_raw_mode();
            return Err(TuiError::Draw(e.to_string()));
        }
    };

    // -- Event reader task ----------------------------------------------------

    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel::<event::Event>(16);
    let event_cancel = cancel.child_token();
    let event_cancel_for_task = event_cancel.clone();
    let event_task = tokio::task::spawn_blocking(move || {
        loop {
            if event_cancel_for_task.is_cancelled() {
                break;
            }
            match event::poll(Duration::from_millis(100)) {
                Ok(true) => {
                    let Ok(evt) = event::read() else { continue };
                    if event_tx.blocking_send(evt).is_err() {
                        break;
                    }
                }
                Ok(false) => {}
                Err(_) => break,
            }
        }
    });

    // -- Render loop ----------------------------------------------------------

    let mut result = {
        let snapshot = snapshot_rx.borrow();
        render_snapshot(&mut terminal, &snapshot)
    };

    if result.is_ok() {
        result = loop {
            tokio::select! {
                () = cancel.cancelled() => break Ok(()),
                maybe_event = event_rx.recv() => {
                    match maybe_event {
                        Some(event::Event::Key(key)) => {
                            if key.kind == event::KeyEventKind::Press {
                                match key.code {
                                    event::KeyCode::Char('q' | 'Q') => break Ok(()),
                                    event::KeyCode::Char('c')
                                        if key.modifiers.contains(event::KeyModifiers::CONTROL) =>
                                    {
                                        break Ok(())
                                    }
                                    _ => {}
                                }
                            }
                        }
                        Some(_) => {}
                        None => break Ok(()),
                    }
                }
                changed = snapshot_rx.changed() => {
                    if changed.is_err() {
                        break Ok(());
                    }
                    let snapshot = snapshot_rx.borrow();
                    if let Err(e) = render_snapshot(&mut terminal, &snapshot) {
                        break Err(e);
                    }
                }
            }
        };
    }

    // -- Teardown ---------------------------------------------------------------

    event_cancel.cancel();
    // Await the blocking task with a short timeout so we don't hang if the
    // terminal driver is stuck, but we give it enough time to observe the
    // cancellation and exit its poll loop.
    let _ = tokio::time::timeout(Duration::from_millis(500), event_task).await;

    let _ = execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        event::DisableMouseCapture,
    );
    let _ = disable_raw_mode();

    result
}

// Forward-declare the backend-free loop so `portal-relay-bin` can call it
// directly when it already owns a terminal (e.g. tests, future refactor).

/// Run the status loop against an injected ratatui terminal backend.
///
/// The current snapshot is rendered once before waiting so tests and future
/// CLIs get an immediate screen even when no update arrives.
///
/// # Errors
///
/// Returns [`TuiError::Draw`] if the backend fails while drawing.
pub async fn run_with_terminal<B>(
    terminal: &mut Terminal<B>,
    mut snapshot_rx: watch::Receiver<StatusSnapshot>,
    cancel: CancellationToken,
) -> Result<(), TuiError>
where
    B: Backend,
    B::Error: Display,
{
    {
        let snapshot = snapshot_rx.borrow();
        render_snapshot(terminal, &snapshot)?;
    }

    loop {
        tokio::select! {
            () = cancel.cancelled() => return Ok(()),
            changed = snapshot_rx.changed() => {
                if changed.is_err() {
                    return Ok(());
                }
                let snapshot = snapshot_rx.borrow();
                render_snapshot(terminal, &snapshot)?;
            }
        }
    }
}

fn render_snapshot<B>(terminal: &mut Terminal<B>, snapshot: &StatusSnapshot) -> Result<(), TuiError>
where
    B: Backend,
    B::Error: Display,
{
    terminal
        .draw(|frame| {
            let view = StatusView::new();
            view.render(frame, frame.area(), snapshot);
        })
        .map_err(|err| TuiError::Draw(err.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;

    fn render_to_lines(snapshot: &StatusSnapshot) -> Vec<String> {
        let backend = TestBackend::new(160, 8);
        let mut terminal = Terminal::new(backend).expect("test backend should initialize");
        terminal
            .draw(|frame| {
                let view = StatusView::new();
                view.render(frame, frame.area(), snapshot);
            })
            .expect("test draw should succeed");

        let buffer = terminal.backend().buffer();
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect()
    }

    fn rendered_text(snapshot: &StatusSnapshot) -> String {
        render_to_lines(snapshot).join("\n")
    }

    #[test]
    fn renders_running_status() {
        let snapshot = StatusSnapshot {
            lifecycle: Lifecycle::Running {
                uptime: Duration::from_hours(1),
            },
            recent_events: Vec::new(),
            lease_count: 7,
            identity_health: IdentityHealth {
                approved: 5,
                pending: 1,
                denied: 2,
                banned: 3,
            },
            bps: BpsAggregate {
                inbound: 100,
                outbound: 23,
            },
        };
        let lines = render_to_lines(&snapshot);
        let text = lines.join("\n");

        assert_eq!(lines.len(), 8);
        assert!(lines[0].contains("Lifecycle"));
        assert!(lines[0].contains("Recent Events"));
        assert!(lines[0].contains("Leases / Identity"));
        assert!(lines[0].contains("BPS"));
        assert!(lines[1].contains("state: Running"));
        assert!(lines[2].contains("uptime: 1h 00m 00s"));
        assert!(lines[1].contains("none"));
        assert!(text.contains("leases active: 7"));
        assert!(text.contains("identity approved: 5"));
        assert!(text.contains("identity pending: 1"));
        assert!(text.contains("identity denied: 2"));
        assert!(text.contains("identity banned: 3"));
        assert!(text.contains("in: 100 B/s"));
        assert!(text.contains("out: 23 B/s"));
        assert!(text.contains("total: 123 B/s"));
    }

    #[test]
    fn renders_stopping_status() {
        let snapshot = StatusSnapshot {
            lifecycle: Lifecycle::Stopping,
            recent_events: vec![RecentEvent::Denial("tenant denied by policy".to_owned())],
            lease_count: 2,
            identity_health: IdentityHealth {
                approved: 1,
                pending: 0,
                denied: 1,
                banned: 0,
            },
            bps: BpsAggregate::default(),
        };
        let text = rendered_text(&snapshot);

        assert!(text.contains("state: Stopping"));
        assert!(text.contains("denial: tenant denied by policy"));
        assert!(text.contains("leases active: 2"));
        assert!(text.contains("identity denied: 1"));
        assert!(text.contains("total: 0 B/s"));
    }

    #[test]
    fn renders_errored_status_with_recent_event_kinds() {
        let snapshot = StatusSnapshot {
            lifecycle: Lifecycle::Errored("janitor task failed".to_owned()),
            recent_events: vec![
                RecentEvent::Throttle("tenant exceeded bps cap".to_owned()),
                RecentEvent::Error("reload parse failed".to_owned()),
            ],
            lease_count: 0,
            identity_health: IdentityHealth::default(),
            bps: BpsAggregate {
                inbound: 1,
                outbound: 2,
            },
        };
        let text = rendered_text(&snapshot);

        assert!(text.contains("state: Errored"));
        assert!(text.contains("error: janitor task failed"));
        assert!(text.contains("throttle: tenant exceeded bps cap"));
        assert!(text.contains("error: reload parse failed"));
        assert!(text.contains("leases active: 0"));
        assert!(text.contains("total: 3 B/s"));
    }

    #[test]
    fn bps_total_saturates_at_u64_max() {
        let snapshot = StatusSnapshot {
            lifecycle: Lifecycle::Running {
                uptime: Duration::from_secs(0),
            },
            recent_events: Vec::new(),
            lease_count: 0,
            identity_health: IdentityHealth::default(),
            bps: BpsAggregate {
                inbound: u64::MAX,
                outbound: 1,
            },
        };
        let text = rendered_text(&snapshot);

        assert!(text.contains("total: 18446744073709551615 B/s"));
    }

    #[tokio::test]
    async fn run_with_terminal_exits_on_cancel_without_snapshot_update() {
        let (_snapshot_tx, snapshot_rx) = watch::channel(StatusSnapshot {
            lifecycle: Lifecycle::Running {
                uptime: Duration::from_secs(0),
            },
            recent_events: Vec::new(),
            lease_count: 1,
            identity_health: IdentityHealth::default(),
            bps: BpsAggregate::default(),
        });
        let cancel = CancellationToken::new();
        cancel.cancel();

        let backend = TestBackend::new(160, 8);
        let mut terminal = Terminal::new(backend).expect("test backend should initialize");

        let result = run_with_terminal(&mut terminal, snapshot_rx, cancel).await;
        assert!(
            result.is_ok(),
            "pre-cancelled status loop should exit cleanly: {result:?}",
        );
    }

    // -------------------------------------------------------------------------
    // Insta snapshot tests — stable diff of terminal buffer across renders.
    // -------------------------------------------------------------------------

    #[test]
    fn snapshot_running() {
        let snapshot = StatusSnapshot {
            lifecycle: Lifecycle::Running {
                uptime: Duration::from_hours(1),
            },
            recent_events: Vec::new(),
            lease_count: 7,
            identity_health: IdentityHealth {
                approved: 5,
                pending: 1,
                denied: 2,
                banned: 3,
            },
            bps: BpsAggregate {
                inbound: 1_200_000,
                outbound: 800_000,
            },
        };
        insta::assert_snapshot!("running", rendered_text(&snapshot));
    }

    #[test]
    fn snapshot_stopping() {
        let snapshot = StatusSnapshot {
            lifecycle: Lifecycle::Stopping,
            recent_events: vec![RecentEvent::Denial(
                "tenant denied by policy".to_owned(),
            )],
            lease_count: 2,
            identity_health: IdentityHealth {
                approved: 1,
                pending: 0,
                denied: 1,
                banned: 0,
            },
            bps: BpsAggregate::default(),
        };
        insta::assert_snapshot!("stopping", rendered_text(&snapshot));
    }

    #[test]
    fn snapshot_errored() {
        let snapshot = StatusSnapshot {
            lifecycle: Lifecycle::Errored("janitor task failed".to_owned()),
            recent_events: vec![
                RecentEvent::Throttle("tenant exceeded bps cap".to_owned()),
                RecentEvent::Error("reload parse failed".to_owned()),
            ],
            lease_count: 0,
            identity_health: IdentityHealth::default(),
            bps: BpsAggregate {
                inbound: 1,
                outbound: 2,
            },
        };
        insta::assert_snapshot!("errored", rendered_text(&snapshot));
    }
}
