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
const DATA_PORT: u16 = 37655;

/// The daemon writes its actual bound admin port to `doclink-admin.port`
/// next to the exe (supports `--port` instances); fall back to the
/// default otherwise.
fn read_admin_port() -> u16 {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let f = dir.join("doclink-admin.port");
            if let Ok(text) = std::fs::read_to_string(&f) {
                if let Ok(port) = text.trim().parse::<u16>() {
                    return port;
                }
            }
        }
    }
    ADMIN_ADDR.1
}

/// Ask the daemon to stop gracefully (admin endpoint), wait for it to
/// exit, and only then fall back to a hard kill.
fn stop_daemon(child: &mut Child, port: u16) {
    use std::io::{Read, Write};
    if let Ok(mut stream) = TcpStream::connect((ADMIN_ADDR.0, port)) {
        let req = format!(
            "POST /v1/admin/shutdown HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        if stream.write_all(req.as_bytes()).is_ok() {
            let mut buf = [0u8; 128];
            let _ = stream.read(&mut buf); // response / EOF
        }
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if !admin_up(port) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // Still up after 5 s: hard kill.
    let _ = child.kill();
    let _ = child.wait();
}

fn admin_up(port: u16) -> bool {
    TcpStream::connect((ADMIN_ADDR.0, port)).is_ok()
}

/// Windows Firewall rules DocLink needs for LAN discovery to work.
/// PrintLink's installer opens the same two rules explicitly — Windows
/// allows the TCP prompt automatically but silently blocks inbound mDNS
/// (UDP 5353 multicast), which is exactly the "can't find each other by
/// ID" failure. We add the rules ourselves since DocLink is portable.
const FW_MDNS_RULE: &str = "DocLink mDNS (UDP 5353)";
const FW_DATA_RULE: &str = "DocLink data (TCP 37655)";

#[cfg(windows)]
fn firewall_rule_exists(name: &str) -> bool {
    Command::new("netsh")
        .args(["advfirewall", "firewall", "show", "rule"])
        .args(["name=".to_string() + name])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains(name))
        .unwrap_or(false)
}

/// Ensure UDP 5353 (mDNS) and TCP 37655 (data plane) are allowed inbound
/// on private networks. One-time; a single UAC prompt runs one inline
/// PowerShell command that adds both rules directly — nothing is written
/// to disk first, so there is no script a local attacker could swap
/// between launch and elevation. Failure (declined/no admin) is non-fatal
/// — pairing with an explicit host:port still works.
#[cfg(windows)]
fn ensure_firewall() {
    use windows::core::{w, PCWSTR};
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

    if firewall_rule_exists(FW_MDNS_RULE) && firewall_rule_exists(FW_DATA_RULE) {
        return;
    }
    let ps = format!(
        "New-NetFirewallRule -DisplayName '{m}' -Direction Inbound -Action Allow -Protocol UDP -LocalPort 5353 -Profile Private | Out-Null; New-NetFirewallRule -DisplayName '{d}' -Direction Inbound -Action Allow -Protocol TCP -LocalPort {p} -Profile Private | Out-Null",
        m = FW_MDNS_RULE,
        d = FW_DATA_RULE,
        p = DATA_PORT
    );
    let params = format!("-NoProfile -NonInteractive -WindowStyle Hidden -Command \"{ps}\"");
    let mut args: Vec<u16> = params.encode_utf16().collect();
    args.push(0);
    unsafe {
        ShellExecuteW(
            HWND(std::ptr::null_mut()),
            w!("runas"),
            w!("powershell.exe"),
            PCWSTR(args.as_ptr()),
            PCWSTR(std::ptr::null()),
            SW_HIDE,
        );
    }
}

fn ensure_daemon() -> Option<Child> {
    if admin_up(read_admin_port()) {
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
                        if admin_up(read_admin_port()) {
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

/// Returns the tray icon; it must be kept alive for the process lifetime,
/// otherwise the icon disappears from the system tray immediately.
#[cfg(windows)]
fn run_tray(proxy: tao::event_loop::EventLoopProxy<String>) -> Option<tray_icon::TrayIcon> {
    use tray_icon::{
        menu::{Menu, MenuEvent, MenuItem},
        TrayIconBuilder,
    };
    let icon = load_icon();
    let menu = Menu::new();
    let open = MenuItem::new("Open", true, None);
    let quit = MenuItem::new("Quit", true, None);
    menu.append(&open).unwrap();
    menu.append(&quit).unwrap();
    let tray = TrayIconBuilder::new()
        .with_icon(icon)
        .with_tooltip("DocLink")
        .with_menu_on_left_click(false)
        .with_menu(Box::new(menu))
        .build()
        .ok()?;
    // tray-icon 0.15 / muda: menu clicks arrive on a global event channel
    // instead of per-item callbacks. Route them to the window event loop.
    let open_id = open.id().clone();
    let quit_id = quit.id().clone();
    let menu_proxy = proxy.clone();
    std::thread::spawn(move || {
        while let Ok(event) = MenuEvent::receiver().recv() {
            if event.id() == &open_id {
                let _ = menu_proxy.send_event("open".to_string());
            } else if event.id() == &quit_id {
                let _ = menu_proxy.send_event("quit".to_string());
            }
        }
    });
    Some(tray)
}

#[cfg(windows)]
fn load_icon() -> tray_icon::Icon {
    // "DL" monogram in a 5x7 pixel font on a rounded blue square, rendered
    // with 4x supersampling for anti-aliased edges.
    const SIZE: u32 = 32;
    const SS: u32 = 4;
    const SCALE: u32 = 3;
    const GLYPH_H: u32 = 7;
    const D: [u8; 7] = [0b11110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b11110];
    const L: [u8; 7] = [0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b11111];

    let glyphs = [D, L];
    let mono_w = (5 * 2 * SCALE + 1) as f32; // 31
    let mono_h = (GLYPH_H * SCALE) as f32; // 21
    let ox = (SIZE as f32 - mono_w) / 2.0;
    let oy = (SIZE as f32 - mono_h) / 2.0;

    let mut rgba = vec![0u8; (SIZE * SIZE * 4) as usize];
    for y in 0..SIZE {
        for x in 0..SIZE {
            let mut acc = [0i32; 4];
            for sy in 0..SS {
                for sx in 0..SS {
                    let px = x as f32 + (sx as f32 + 0.5) / SS as f32;
                    let py = y as f32 + (sy as f32 + 0.5) / SS as f32;
                    let c = sample_icon(px, py, &glyphs, ox, oy);
                    for i in 0..4 {
                        acc[i] += c[i] as i32;
                    }
                }
            }
            let n = (SS * SS) as i32;
            let idx = ((y * SIZE + x) * 4) as usize;
            for i in 0..4 {
                rgba[idx + i] = (acc[i] / n) as u8;
            }
        }
    }
    tray_icon::Icon::from_rgba(rgba, SIZE, SIZE).unwrap()
}

#[cfg(windows)]
fn sample_icon(px: f32, py: f32, glyphs: &[[u8; 7]; 2], ox: f32, oy: f32) -> [u8; 4] {
    const BG: [u8; 4] = [0x00, 0x78, 0xd4, 0xFF];
    const FG: [u8; 4] = [0xff, 0xff, 0xff, 0xff];
    let in_bg = rounded_rect(px - 16.0, py - 16.0, 15.0, 6.0);

    let rx = px - ox;
    let ry = py - oy;
    let cx = (rx / 3.0).floor() as i32;
    let cy = (ry / 3.0).floor() as i32;
    let mut on = false;
    if (0..7).contains(&cy) {
        let (gi, lc) = if (0..=4).contains(&cx) {
            (0, cx)
        } else if (6..=10).contains(&cx) {
            (1, cx - 6)
        } else {
            (-1, 0)
        };
        if gi >= 0 {
            on = (glyphs[gi as usize][cy as usize] >> (4 - lc)) & 1 == 1;
        }
    }
    if on {
        FG
    } else if in_bg {
        BG
    } else {
        [0, 0, 0, 0]
    }
}

#[cfg(windows)]
fn rounded_rect(ax: f32, ay: f32, half: f32, corner: f32) -> bool {
    let dx = ax.abs() - (half - corner);
    let dy = ay.abs() - (half - corner);
    if dx > 0.0 && dy > 0.0 {
        dx * dx + dy * dy <= corner * corner
    } else if dx > 0.0 {
        dx <= corner
    } else if dy > 0.0 {
        dy <= corner
    } else {
        true
    }
}

fn main() -> wry::Result<()> {
    #[cfg(windows)]
    ensure_firewall();

    let mut child = ensure_daemon();
    let admin_port = read_admin_port();
    let admin_url = format!("http://127.0.0.1:{admin_port}");

    let event_loop = EventLoopBuilder::<String>::with_user_event().build();
    let proxy = event_loop.create_proxy();

    #[cfg(windows)]
    let _tray = run_tray(proxy.clone());

    let window = WindowBuilder::new()
        .with_title("DocLink")
        .with_decorations(false)
        .with_inner_size(LogicalSize::new(1120.0, 740.0))
        .with_min_inner_size(LogicalSize::new(800.0, 520.0))
        .build(&event_loop)
        .expect("failed to create window");

    let _webview = WebViewBuilder::new()
        .with_url(&admin_url)
        .with_ipc_handler(move |req| {
            let _ = proxy.send_event(req.body().clone());
        })
        .build(&window)?;

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
                    // Exit the app; stop the daemon we spawned gracefully
                    // first (a daemon we did not start is left alone).
                    if let Some(d) = child.as_mut() {
                        stop_daemon(d, admin_port);
                    }
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
