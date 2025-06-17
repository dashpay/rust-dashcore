//! Terminal UI utilities for displaying status information.

use std::io::{self, Write};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};
use crossterm::{
    cursor,
    execute,
    style::{Stylize, Print},
    terminal::{self, ClearType},
    QueueableCommand,
};

/// Status information to display in the terminal
#[derive(Clone, Default)]
pub struct TerminalStatus {
    pub headers: u32,
    pub filter_headers: u32,
    pub chainlock_height: Option<u32>,
    pub peer_count: usize,
    pub network: String,
}

/// Terminal UI manager for displaying status
pub struct TerminalUI {
    status: Arc<RwLock<TerminalStatus>>,
    enabled: bool,
}

impl TerminalUI {
    /// Create a new terminal UI manager
    pub fn new(enabled: bool) -> Self {
        Self {
            status: Arc::new(RwLock::new(TerminalStatus::default())),
            enabled,
        }
    }

    /// Get a handle to update the status
    pub fn status_handle(&self) -> Arc<RwLock<TerminalStatus>> {
        self.status.clone()
    }

    /// Initialize the terminal UI
    pub fn init(&self) -> io::Result<()> {
        if !self.enabled {
            return Ok(());
        }

        // Don't clear screen or hide cursor - we want normal log output
        // Just add some space for the status bar
        println!(); // Add blank line before status bar
        
        Ok(())
    }

    /// Cleanup terminal UI
    pub fn cleanup(&self) -> io::Result<()> {
        if !self.enabled {
            return Ok(());
        }

        // Restore terminal
        execute!(
            io::stdout(),
            cursor::Show,
            cursor::MoveTo(0, terminal::size()?.1)
        )?;
        
        println!(); // Add a newline after the status bar

        Ok(())
    }

    /// Draw just the status bar at the bottom
    pub async fn draw(&self) -> io::Result<()> {
        if !self.enabled {
            return Ok(());
        }

        let status = self.status.read().await;
        let (width, height) = terminal::size()?;
        
        // Lock stdout for the entire draw operation
        let mut stdout = io::stdout();
        
        // Save cursor position
        stdout.queue(cursor::SavePosition)?;
        
        // Check if terminal is large enough
        if height < 2 {
            // Terminal too small to draw status bar
            stdout.queue(cursor::RestorePosition)?;
            return stdout.flush();
        }
        
        // Draw separator line
        stdout.queue(cursor::MoveTo(0, height - 2))?;
        stdout.queue(terminal::Clear(ClearType::CurrentLine))?;
        stdout.queue(Print("─".repeat(width as usize).dark_grey()))?;
        
        // Draw status bar
        stdout.queue(cursor::MoveTo(0, height - 1))?;
        stdout.queue(terminal::Clear(ClearType::CurrentLine))?;
        
        // Format status bar
        let status_text = format!(
            " {} {} │ {} {} │ {} {} │ {} {} │ {} {}",
            "Headers:".cyan().bold(),
            format_number(status.headers).white(),
            "Filters:".cyan().bold(),
            format_number(status.filter_headers).white(),
            "ChainLock:".cyan().bold(),
            status.chainlock_height
                .map(|h| format!("#{}", format_number(h)))
                .unwrap_or_else(|| "None".to_string())
                .yellow(),
            "Peers:".cyan().bold(),
            status.peer_count.to_string().white(),
            "Network:".cyan().bold(),
            status.network.clone().green()
        );

        stdout.queue(Print(&status_text))?;
        
        // Add padding to fill the rest of the line
        let status_len = strip_ansi_codes(&status_text).len();
        if status_len < width as usize {
            stdout.queue(Print(" ".repeat(width as usize - status_len)))?;
        }
        
        // Restore cursor position
        stdout.queue(cursor::RestorePosition)?;
        
        stdout.flush()?;
        
        Ok(())
    }

    /// Update status and redraw
    pub async fn update_status<F>(&self, updater: F) -> io::Result<()>
    where
        F: FnOnce(&mut TerminalStatus),
    {
        {
            let mut status = self.status.write().await;
            updater(&mut status);
        }
        self.draw().await
    }

    /// Start the UI update loop
    pub fn start_update_loop(self: Arc<Self>) {
        if !self.enabled {
            return;
        }

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_millis(100)); // Update 10 times per second
            
            loop {
                interval.tick().await;
                if let Err(e) = self.draw().await {
                    eprintln!("Terminal UI error: {}", e);
                    break;
                }
            }
        });
    }
}

/// Format a number with thousand separators
fn format_number(n: u32) -> String {
    let s = n.to_string();
    let mut result = String::new();
    let mut count = 0;
    
    for ch in s.chars().rev() {
        if count > 0 && count % 3 == 0 {
            result.push(',');
        }
        result.push(ch);
        count += 1;
    }
    
    result.chars().rev().collect()
}

/// Strip ANSI color codes for length calculation
fn strip_ansi_codes(s: &str) -> String {
    // Simple implementation - in production you'd use a proper ANSI stripping library
    let mut result = String::new();
    let mut in_escape = false;
    
    for ch in s.chars() {
        if ch == '\x1b' {
            in_escape = true;
        } else if in_escape && ch == 'm' {
            in_escape = false;
        } else if !in_escape {
            result.push(ch);
        }
    }
    
    result
}

/// RAII guard for terminal UI cleanup
pub struct TerminalGuard {
    ui: Arc<TerminalUI>,
}

impl TerminalGuard {
    pub fn new(ui: Arc<TerminalUI>) -> io::Result<Self> {
        ui.init()?;
        ui.clone().start_update_loop();
        Ok(Self { ui })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = self.ui.cleanup();
    }
}

