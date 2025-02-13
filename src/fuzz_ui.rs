use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use libafl::prelude::{current_time, format_duration_hms};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    io::{self, Stdout},
    time::{Duration, Instant},
};
use tui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::Span,
    widgets::{Axis, Block, Borders, Chart, Dataset, GraphType, List, ListItem},
    Frame, Terminal,
};

use crate::causes::list_causes;

// Every nth corpus increase that should be logged.
const EVERY_N_CORPUS: u64 = 1000;

pub struct TimeData {
    // The time when this data point was created.
    time: f64,
    // The corpus size at this data point.
    corpus_size: u64,
    // the time per finding since the last time data group.
    rel_time: f64,
}

pub struct FuzzUIData {
    pub max_coverage: Vec<(f64, f64)>,
    pub time_since_last_find: Vec<TimeData>,
    time_since_last_find_group: f64,
    start_time: std::time::Duration,
    messages: VecDeque<String>,
}

impl FuzzUIData {
    pub fn get_max_coverage(&self) -> f64 {
        self.max_coverage.last().ok_or((0.0, 0.0)).unwrap().1
    }

    pub fn add_max_coverage(&mut self, value: f64) {
        if self.max_coverage.is_empty() || self.max_coverage.last().unwrap().1 < value {
            self.max_coverage.push((self.rel_time_secs(), value))
        }
        // Only keep the last 200 messages as we won't be able to display
        // more than that with any reasonable terminal size.
        self.max_coverage.shrink_to(200);
    }

    pub fn add_corpus_size(&mut self, corpus_size: u64) {
        // Keep track how long it took us to find the newest corpus item.
        let last = self.time_since_last_find.last().unwrap();
        let time = self.rel_time_secs();
        let rel_time = (time - last.time) / (EVERY_N_CORPUS as f64);
        self.time_since_last_find_group = rel_time;

        // Just few findings, we store the relative time to make a nice graph
        // in the UI.
        if last.corpus_size + EVERY_N_CORPUS >= corpus_size {
            return;
        }

        self.time_since_last_find.push(TimeData {
            time: time,
            corpus_size: corpus_size,
            rel_time: rel_time,
        });
    }

    pub fn add_message(&mut self, value: String) {
        self.messages.push_front(value);
    }

    fn rel_time_secs(&self) -> f64 {
        (current_time() - self.start_time).as_secs_f64()
    }
}

pub struct FuzzUI {
    terminal: Option<Terminal<CrosstermBackend<Stdout>>>,
    last_tick: Instant,
    data: FuzzUIData,
}

impl FuzzUI {
    pub fn new(simple_ui: bool) -> FuzzUI {
        let mut data = FuzzUIData {
            max_coverage: Vec::<(f64, f64)>::new(),
            time_since_last_find: Vec::<TimeData>::new(),
            time_since_last_find_group: 0.0,
            start_time: current_time(),
            messages: VecDeque::<String>::new(),
        };
        data.time_since_last_find.push(TimeData {
            time: 0.0,
            corpus_size: 0,
            rel_time: 0.0,
        });

        if !simple_ui {
            // setup terminal
            enable_raw_mode().expect("Failed to enable raw terminal mode");
            let mut stdout = io::stdout();
            execute!(stdout, EnterAlternateScreen, EnableMouseCapture)
                .expect("Failed to enable terminal mode");
            let backend = CrosstermBackend::new(stdout);
            let terminal = Terminal::new(backend).expect("Failed to create terminal wrapper");
            FuzzUI {
                terminal: Some(terminal),
                last_tick: Instant::now(),
                data,
            }
        } else {
            FuzzUI {
                terminal: None,
                last_tick: Instant::now(),
                data,
            }
        }
    }

    pub fn data(&mut self) -> &mut FuzzUIData {
        &mut self.data
    }

    fn on_tick(&mut self) {
        if let Some(term) = self.terminal.as_mut() {
            term.draw(|f| ui(f, &self.data)).unwrap();
        } else {
            if !self.data.messages.is_empty() {
                println!("{}", self.data.messages.front().unwrap());
            }
        }
    }

    pub fn try_tick(&mut self) {
        let tick_rate = Duration::from_millis(250);

        if self.last_tick.elapsed() >= tick_rate {
            self.on_tick();
            self.last_tick = Instant::now();
        }
    }
}

impl Drop for FuzzUI {
    fn drop(&mut self) {
        if let Some(term) = self.terminal.as_mut() {
            // restore terminal
            disable_raw_mode().unwrap();
            execute!(
                term.backend_mut(),
                LeaveAlternateScreen,
                DisableMouseCapture
            )
            .unwrap();
            term.show_cursor().unwrap();
        }
    }
}

fn summarize_findings(data: &FuzzUIData) -> Vec<String> {
    let case_list = list_causes(data.start_time);

    let mut dupes = HashMap::<String, u64>::new();
    for case in &case_list.found {
        dupes.insert(
            case.cause.clone(),
            dupes.get(&case.cause).or(Some(&0)).unwrap() + 1,
        );
    }

    let mut emitted_causes = HashSet::<String>::new();

    let mut result = Vec::<String>::new();
    for case in &case_list.found {
        if !emitted_causes.insert(case.cause.clone()) {
            continue;
        }
        let res = format!(
            "{} (TTE: {}) Dupes: {}",
            case.cause,
            format_duration_hms(&case.time_to_exposure),
            dupes.get(&case.cause).unwrap()
        );
        result.push(res);
    }
    for case in &case_list.still_missing {
        let res = format!("{} (Missing)", case);
        result.push(res);
    }
    result
}

fn render_coverage<B: Backend>(f: &mut Frame<B>, data: &FuzzUIData, chunk: Rect) {
    let last_slot = data
        .max_coverage
        .last()
        .or(Some(&(1.0 as f64, 10.0 as f64)))
        .unwrap()
        .clone();

    let coverage = data.max_coverage.clone();

    let max_time = format_duration_hms(&(current_time() - data.start_time));

    let datasets = vec![
        Dataset::default()
            .name("")
            .marker(symbols::Marker::Braille)
            .style(Style::default().fg(Color::White))
            .graph_type(GraphType::Line)
            .data(coverage.as_slice()),
        Dataset::default()
            .name("")
            .marker(symbols::Marker::Braille)
            .style(Style::default().fg(Color::Red))
            .graph_type(GraphType::Scatter)
            .data(coverage.as_slice()),
    ];

    let chart = Chart::new(datasets)
        .block(
            Block::default()
                .title(Span::styled(
                    "Coverage",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ))
                .borders(Borders::ALL),
        )
        .x_axis(
            Axis::default()
                .title("Elapsed time (s)")
                .style(Style::default().fg(Color::Gray))
                .bounds([0.0, data.rel_time_secs()])
                .labels(vec![
                    Span::styled("0", Style::default().add_modifier(Modifier::BOLD)),
                    Span::styled(
                        format!("{}", max_time),
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                ]),
        )
        .y_axis(
            Axis::default()
                .title("Coverage")
                .style(Style::default().fg(Color::Gray))
                .bounds([0.0, last_slot.1 * 1.2])
                .labels(vec![
                    Span::styled("0", Style::default().add_modifier(Modifier::BOLD)),
                    Span::styled(
                        format!("{:0}", last_slot.1),
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                ]),
        );
    f.render_widget(chart, chunk);
}

fn render_time_between_findings<B: Backend>(f: &mut Frame<B>, data: &FuzzUIData, chunk: Rect) {
    let max_time = format_duration_hms(&(current_time() - data.start_time));

    let mut max_rel_time = 0.0;
    for time in &data.time_since_last_find {
        if time.rel_time > max_rel_time {
            max_rel_time = time.rel_time;
        }
    }

    let mut rel_time_list: Vec<(f64, f64)> = data
        .time_since_last_find
        .iter()
        .map(|time_data| (time_data.time, time_data.rel_time))
        .collect();
    rel_time_list.push((data.rel_time_secs(), data.time_since_last_find_group));

    let datasets = vec![Dataset::default()
        .name("")
        .marker(symbols::Marker::Braille)
        .style(Style::default().fg(Color::Yellow))
        .graph_type(GraphType::Line)
        .data(rel_time_list.as_slice())];

    let chart = Chart::new(datasets)
        .block(
            Block::default()
                .title(Span::styled(
                    "Time between corpus findings",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ))
                .borders(Borders::ALL),
        )
        .x_axis(
            Axis::default()
                .title("Elapsed time (ms)")
                .style(Style::default().fg(Color::Gray))
                .bounds([0.0, data.rel_time_secs()])
                .labels(vec![
                    Span::styled("0", Style::default().add_modifier(Modifier::BOLD)),
                    Span::styled(
                        format!("{}", max_time),
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                ]),
        )
        .y_axis(
            Axis::default()
                .title("Time since last find (s)")
                .style(Style::default().fg(Color::Gray))
                .bounds([0.0, max_rel_time * 1.2])
                .labels(vec![
                    Span::styled("0", Style::default().add_modifier(Modifier::BOLD)),
                    Span::styled(
                        format!("{:.2}", max_rel_time),
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                ]),
        );
    f.render_widget(chart, chunk);
}

fn ui<B: Backend>(f: &mut Frame<B>, data: &FuzzUIData) {
    let size = f.size();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(size);

    let top_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(10), Constraint::Length(70)])
        .split(chunks[0]);

    let bottom_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

    let cause_list = summarize_findings(data);

    let findings: Vec<ListItem> = cause_list
        .iter()
        .map(|i| {
            if i.contains("Missing") {
                ListItem::new(i.as_str()).style(Style::default().fg(Color::Red))
            } else {
                ListItem::new(i.as_str()).style(Style::default())
            }
        })
        .collect();
    let findings_list =
        List::new(findings).block(Block::default().borders(Borders::ALL).title("Findings"));

    f.render_widget(findings_list, top_chunks[1]);

    // Iterate through all elements in the `items` app and append some debug text to it.
    let items: Vec<ListItem> = data
        .messages
        .iter()
        .map(|i| ListItem::new(i.as_str()).style(Style::default()))
        .collect();

    let items = List::new(items).block(Block::default().borders(Borders::ALL).title("Messages"));

    // We can now render the item list
    f.render_widget(items, top_chunks[0]);

    render_coverage(f, data, bottom_chunks[0]);
    render_time_between_findings(f, data, bottom_chunks[1]);
}
