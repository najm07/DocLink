//! DocLink window: a small WebView2 shell around the local admin UI.
//!
//! Double-click UX for testing: if the daemon's admin plane isn't up,
//! spawn doclinkd.exe from the same folder, wait for it, then open the
//! window. Closing the window does NOT stop the daemon — sharing keeps
//! working in the background.
//!
//! Note: tao is a direct dependency (pinned to match wry's internal
//! version — see Cargo.toml), never import it through wry.

#![windows_subsystem = "windows"]

use std::net::TcpStream;
use std::time::{Duration, Instant};
use tao::{
    dpi::LogicalSize,
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoop},
    window::WindowBuilder,
};
use wry::WebViewBuilder;

// Admin plane = data plane + 1 (see doclink_core::protocol::DEFAULT_HTTP_PORT).
// TODO(M3): read doclink.toml next to the exe in case http_port is overridden.
const ADMIN_ADDR: (&str, u16) = ("127.0.0.1", 37656);
const ADMIN_URL: &str = "http://127.0.0.1:37656";

fn admin_up() -> bool {
    TcpStream::connect(ADMIN_ADDR).is_ok()
}

/// Start doclinkd.exe (same folder as this exe) if the admin plane is down,
/// then wait until it answers (up to 15 s).
fn ensure_daemon() {
    if admin_up() {
        return;
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let daemon = dir.join("doclinkd.exe");
            if daemon.exists() {
                // The daemon is a console app: it gets its own console
                // window with live logs — useful during testing.
                let _ = std::process::Command::new(daemon).spawn();
            }
        }
    }
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if admin_up() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn main() -> wry::Result<()> {
    ensure_daemon();

    let event_loop = EventLoop::new();
    let window = WindowBuilder::new()
        .with_title("DocLink")
        .with_inner_size(LogicalSize::new(1080.0, 720.0))
        .build(&event_loop)
        .expect("failed to create window");

    let _webview = WebViewBuilder::new()
        .with_url(ADMIN_URL)
        .build(&window)?;

    // tao's run() diverges and returns () — the process exits here.
    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        if let Event::WindowEvent {
            event: WindowEvent::CloseRequested,
            ..
        } = event
        {
            *control_flow = ControlFlow::Exit;
        }
    });
    #[allow(unreachable_code)]
    Ok(())
}
