//! DocLink window: a small WebView2 shell around the local admin UI.
//!
//! Frameless on purpose — the web UI draws a VS Code-style title bar
//! and talks to this process over IPC (drag / min / max / close).
//! Closing the window hides it to tray; the daemon keeps running.
//! Right-click the tray icon to Open or Quit.

#![windows_subsystem = "windows"]

use std::fs::File;
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tao::{
    dpi::LogicalSize,
    event::{Event, StartCause, WindowEvent},
    event_loop::{ControlFlow, EventLoopBuilder},
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

fn ensure_daemon() -> Option<Child> {
    if admin_up() {
        return None; // already running (e.g. from a previous window)
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
                if let Ok(child) = cmd.spawn() {
                    // Wait up to 15 s for the admin plane to become reachable.
                    let deadline = Instant::now() + Duration::from_secs(15);
                    while Instant::now() < deadline {
                        if admin_up() {
                            return Some(child);
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
            }
        }
    }
    None
}

#[cfg(windows)]
fn run_tray(event_loop: &tao::event_loop::EventLoop<String>, proxy: tao::event_loop::EventLoopProxy<String>) {
    use tray_icon::{
        menu::{Menu, MenuItem},
        TrayIconBuilder,
    };
    let icon = load_icon();
    let menu = Menu::new();
    let open = MenuItem::new("Open", true, None);
    let quit = MenuItem::new("Quit", true, None);
    menu.append(&open).unwrap();
    menu.append(&quit).unwrap();
    let _tray = TrayIconBuilder::new()
        .with_icon(icon)
        .with_tooltip("DocLink")
        .with_menu_on_left_click(false)
        .with_menu(Box::new(menu))
        .build()
        .unwrap();
    let open_proxy = proxy.clone();
    let quit_proxy = proxy.clone();
    open.register_action(move |_| {
        let _ = open_proxy.send_event("open".to_string());
    });
    quit.register_action(move |_| {
        let _ = quit_proxy.send_event("quit".to_string());
    });
}

#[cfg(windows)]
fn load_icon() -> tray_icon::Icon {
    // Simple blue square icon (32x32).
    let (width, height) = (32, 32);
    let mut rgba = Vec::with_capacity(width as usize * height as usize * 4);
    for _ in 0..(width * height) {
        rgba.extend_from_slice(&[0x00, 0x78, 0xd4, 0xFF]);
    }
    tray_icon::Icon::from_rgba(rgba, width, height).unwrap()
}

fn main() -> wry::Result<()> {
    let _child = ensure_daemon();

    let event_loop = EventLoopBuilder::<String>::with_user_event().build();
    let proxy = event_loop.create_proxy();

    #[cfg(windows)]
    run_tray(&event_loop, proxy.clone());

    let window = WindowBuilder::new()
        .with_title("DocLink")
        .with_decorations(false)
        .with_inner_size(LogicalSize::new(1120.0, 740.0))
        .with_min_inner_size(LogicalSize::new(800.0, 520.0))
        .build(&event_loop)
        .expect("failed to create window");

    let _webview = WebViewBuilder::new(&window)
        .with_url(ADMIN_URL)
        .with_ipc_handler(move |req| {
            let _ = proxy.send_event(req.body().clone());
        })
        .build()?;

    let visible = Arc::new(AtomicBool::new(true));
    let visible_clone = visible.clone();

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        match event {
            Event::NewEvents(StartCause::Init) => {
                // Window starts visible.
            }
            Event::UserEvent(cmd) => match cmd.as_str() {
                "drag" => {
                    let _ = window.drag_window();
                }
                "minimize" => window.set_minimized(true),
                "maximize" => window.set_maximized(!window.is_maximized()),
                "close" => {
                    // Hide to tray instead of exiting.
                    window.set_visible(false);
                    visible_clone.store(false, Ordering::SeqCst);
                }
                "open" => {
                    window.set_visible(true);
                    window.set_focus();
                    visible_clone.store(true, Ordering::SeqCst);
                }
                "quit" => {
                    *control_flow = ControlFlow::Exit;
                }
                _ => {}
            },
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                // Intercept × and hide to tray.
                window.set_visible(false);
                visible_clone.store(false, Ordering::SeqCst);
            }
            _ => {}
        }
    });
    #[allow(unreachable_code)]
    Ok(())
}
