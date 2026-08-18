//! DocLink window: a small WebView2 shell around the local admin UI.
//!
//! Double-click UX: if the daemon's admin plane isn't up, spawn
//! doclinkd.exe from the same folder (no console window), wait for it,
//! then open the window. Closing the window does NOT stop the daemon —
//! sharing keeps working in the background.
//!
//! Note: tao is a direct dependency (pinned to match wry's internal
//! version — see Cargo.toml), never import it through wry.

#![windows_subsystem = "windows"]

use std::fs::File;
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tao::{
    dpi::LogicalSize,
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoop},
    window::WindowBuilder,
};
use wry::WebViewBuilder;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

// CREATE_NO_WINDOW: spawn a console-subsystem process without allocating
// a visible terminal. Logs go to doclinkd.log next to the exe instead.
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

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
                let mut cmd = Command::new(&daemon);
                cmd.current_dir(dir);
                #[cfg(windows)]
                {
                    cmd.creation_flags(CREATE_NO_WINDOW);
                }
                if let Ok(log) = File::create(dir.join("doclinkd.log")) {
                    if let Ok(err) = log.try_clone() {
                        cmd.stdout(Stdio::from(log));
                        cmd.stderr(Stdio::from(err));
                    }
                }
                let _ = cmd.spawn();
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
        .with_inner_size(LogicalSize::new(1120.0, 740.0))
        .with_min_inner_size(LogicalSize::new(820.0, 560.0))
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
