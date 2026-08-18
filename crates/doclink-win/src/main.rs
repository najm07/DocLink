//! DocLink window: a small WebView2 shell around the local admin UI.
//!
//! Frameless on purpose — the web UI draws a VS Code-style title bar
//! and talks to this process over IPC (drag / min / max / close).
//! Closing the window does NOT stop the daemon.

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

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

const ADMIN_ADDR: (&str, u16) = ("127.0.0.1", 37656);
const ADMIN_URL: &str = "http://127.0.0.1:37656";

fn admin_up() -> bool {
    TcpStream::connect(ADMIN_ADDR).is_ok()
}

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

    let event_loop = EventLoop::<String>::with_user_event();
    let proxy = event_loop.create_proxy();

    let window = WindowBuilder::new()
        .with_title("DocLink")
        .with_decorations(false)
        .with_inner_size(LogicalSize::new(1120.0, 740.0))
        .with_min_inner_size(LogicalSize::new(800.0, 520.0))
        .build(&event_loop)
        .expect("failed to create window");

    let _webview = WebViewBuilder::new()
        .with_url(ADMIN_URL)
        .with_ipc_handler(move |req| {
            let _ = proxy.send_event(req.body().clone());
        })
        .build(&window)?;

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        match event {
            Event::UserEvent(cmd) => match cmd.as_str() {
                "drag" => {
                    let _ = window.drag_window();
                }
                "minimize" => window.set_minimized(true),
                "maximize" => window.set_maximized(!window.is_maximized()),
                "close" => *control_flow = ControlFlow::Exit,
                _ => {}
            },
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => *control_flow = ControlFlow::Exit,
            _ => {}
        }
    });
    #[allow(unreachable_code)]
    Ok(())
}
