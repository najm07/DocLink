//! Optional auto-update: check GitHub releases for a newer DocLink.
//!
//! Update checking is opt-out (`check_updates` in doclink.toml). When on,
//! the daemon phones the GitHub API every six hours, and the UI surfaces
//! a one-click apply. Downloads use a plain HTTPS client (the peering
//! client disables cert validation for pinned-peer TLS and must never be
//! reused for internet traffic).

use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// App build version as shipped (workspace Cargo version, "0.2.0").
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Set to the repo owner/name at release time. Only this one upstream is
/// ever contacted, so the toggle is a hard privacy boundary.
const REPO_API: &str = "https://api.github.com/repos/najm07/doclink/releases/latest";
const CHECK_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// Result of one check against GitHub.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateStatus {
    pub current: String,
    pub latest: String,
    pub prerelease: bool,
    /// Direct URL of the portable zip asset, when present.
    pub download_url: Option<String>,
    /// Direct URL of the MSI asset, when present.
    pub msi_url: Option<String>,
    pub release_notes: Option<String>,
    pub published_at: Option<String>,
}

/// Runtime snapshot of the check/download lifecycle, threaded through
/// the admin plane for the UI to poll.
#[derive(Debug, Default)]
pub struct UpdateOverride {
    pub inner: Mutex<State>,
}

#[derive(Debug, Default, Clone)]
pub struct State {
    pub last_check_unix: Option<u64>,
    pub status: Option<UpdateStatus>,
    pub checking: bool,
    /// 0.0..1.0 while a download is in flight, then None when done.
    pub downloading: Option<f32>,
    pub error: Option<String>,
    pub applied: bool,
}

/// Split ("3.1.4" or "v3.1.4") into comparable parts.
pub fn parse_version(v: &str) -> Option<(u32, u32, u32)> {
    let v = v.trim().trim_start_matches(['v', 'V']);
    let mut bits = v.split('.');
    let major = bits.next()?.trim().parse().ok()?;
    let minor = bits.next().unwrap_or("0").trim().parse().ok()?;
    let patch = bits.next().unwrap_or("0").trim().parse().ok()?;
    Some((major, minor, patch))
}

/// Is `candidate` a strictly newer version than `baseline`?
pub fn version_gt(candidate: &str, baseline: &str) -> bool {
    match (parse_version(candidate), parse_version(baseline)) {
        (Some(a), Some(b)) => a > b,
        (Some(_), None) => true, // unparseable baseline => treat as behind
        _ => false,
    }
}

/// CA-verifying client for internet traffic only.
pub fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .build()
        .expect("updater http client")
}

#[derive(Deserialize)]
struct GhRelease {
    tag_name: String,
    prerelease: bool,
    published_at: Option<String>,
    body: Option<String>,
    assets: Vec<GhAsset>,
}

#[derive(Deserialize)]
struct GhAsset {
    name: String,
    browser_download_url: String,
}

/// Query GitHub for the newest non-prerelease DocLink build. Returns
/// None when already on the latest. Network errors carry their own
/// message so the UI can say "check failed" rather than crash.
pub async fn check_latest(
    http: &reqwest::Client,
) -> Result<Option<UpdateStatus>, String> {
    let resp = http
        .get(REPO_API)
        .header(reqwest::header::USER_AGENT, "doclink-updater")
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("cannot reach GitHub: {e}"))?;
    let status = resp.status();
    let body = resp.text().await.map_err(|e| format!("read response: {e}"))?;
    if status == reqwest::StatusCode::FORBIDDEN && body.contains("rate limit") {
        return Err("GitHub rate limit reached — try again later".into());
    }
    if !status.is_success() {
        return Err(format!("GitHub replied {status}"));
    }
    let rel: GhRelease =
        serde_json::from_str(&body).map_err(|e| format!("bad release payload: {e}"))?;
    if !version_gt(&rel.tag_name, APP_VERSION) {
        return Ok(None);
    }
    let mut download_url = None;
    let mut msi_url = None;
    for a in &rel.assets {
        if a.name.ends_with(".zip") {
            download_url = Some(a.browser_download_url.clone());
        } else if a.name.ends_with(".msi") {
            msi_url = Some(a.browser_download_url.clone());
        }
    }
    Ok(Some(UpdateStatus {
        current: APP_VERSION.to_string(),
        latest: rel.tag_name.trim_start_matches(['v', 'V']).to_string(),
        prerelease: rel.prerelease,
        download_url,
        msi_url,
        release_notes: rel.body,
        published_at: rel.published_at,
    }))
}

/// Periodic check loop: one call right after startup (so a fresh install
/// surfaces an update immediately), then every CHECK_INTERVAL while the
/// toggle stays on.
pub async fn run_check_loop(
    http: reqwest::Client,
    enabled: Arc<std::sync::atomic::AtomicBool>,
    shared: Arc<UpdateOverride>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    use std::sync::atomic::Ordering;
    if enabled.load(Ordering::Relaxed) && run_check(&http, &shared).await.is_err() {
        tracing::warn!("initial update check failed (offline?) — will retry later");
    }
    let mut tick = tokio::time::interval(CHECK_INTERVAL);
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = tick.tick() => {
                if enabled.load(Ordering::Relaxed) {
                    let _ = run_check(&http, &shared).await;
                }
            }
        }
    }
}

/// One check, updating shared state. Errors are captured in `shared`
/// so the UI's next poll can display them.
pub async fn run_check(http: &reqwest::Client, shared: &Arc<UpdateOverride>) -> Result<(), ()> {
    {
        let mut st = shared.inner.lock().unwrap();
        st.checking = true;
        st.error = None;
    }
    let outcome = check_latest(http).await;
    let mut st = shared.inner.lock().unwrap();
    st.checking = false;
    st.last_check_unix = Some(now_unix());
    match outcome {
        Ok(Some(status)) => {
            st.status = Some(status);
            st.applied = false;
            Ok(())
        }
        Ok(None) => {
            st.status = Some(UpdateStatus {
                current: APP_VERSION.to_string(),
                latest: APP_VERSION.to_string(),
                prerelease: false,
                download_url: None,
                msi_url: None,
                release_notes: None,
                published_at: None,
            });
            Ok(())
        }
        Err(e) => {
            st.error = Some(e);
            Err(())
        }
    }
}

fn now_unix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Where the app lives (the daemon's own folder — next to doclink-win.exe
/// in the portable layout).
fn app_dir() -> std::path::PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}

/// Fixed apply script. All dynamic paths arrive via environment
/// variables, so no quoting/escaping of user-visible paths is needed.
const APPLY_SCRIPT: &str = r#"
Start-Sleep -Seconds 2
Stop-Process -Name 'doclinkd','doclink-win' -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 600
if (Test-Path "$env:DL_STAGE\doclinkd.exe") {
  Copy-Item -Force "$env:DL_STAGE\doclinkd.exe" "$env:DL_APPDIR\doclinkd.exe"
  Copy-Item -Force "$env:DL_STAGE\doclink-win.exe" "$env:DL_APPDIR\doclink-win.exe"
}
Remove-Item -Recurse -Force "$env:DL_STAGE","$env:DL_ZIP" -ErrorAction SilentlyContinue
Start-Process -FilePath "$env:DL_APPDIR\doclink-win.exe" -WorkingDirectory "$env:DL_APPDIR"
"#;

/// Download-and-apply with a delay: stage the new binaries, hand a small
/// detached script the relocation job, and let it restart the window.
/// Returns a human message (the daemon shuts down moments later either way).
pub async fn apply_update(
    shared: &Arc<UpdateOverride>,
    http: &reqwest::Client,
) -> Result<String, String> {
    let status = {
        let st = shared.inner.lock().unwrap();
        st.status
            .as_ref()
            .filter(|s| version_gt(&s.latest, APP_VERSION))
            .cloned()
            .ok_or_else(|| "no update matched for apply".to_string())?
    };

    let url = status
        .download_url
        .clone()
        .ok_or_else(|| "no portable build published for this release".to_string())?;

    {
        let mut st = shared.inner.lock().unwrap();
        st.downloading = Some(0.0);
        st.error = None;
        st.applied = false;
    }

    let zip_dest = std::env::temp_dir().join(format!("doclink-update-{}.zip", std::process::id()));
    let stage = std::env::temp_dir().join(format!("doclink-stage-{}", std::process::id()));

    let result = download_and_stage(&url, &zip_dest, &stage, shared, http).await;

    if let Err(e) = &result {
        let mut st = shared.inner.lock().unwrap();
        st.downloading = None;
        st.error = Some(e.clone());
    }
    result
}

/// Download the release zip, unpack it into a staging dir, and hand a
/// detached script the job of swapping the binaries and restarting.
async fn download_and_stage(
    url: &str,
    zip_dest: &std::path::Path,
    stage: &std::path::Path,
    shared: &Arc<UpdateOverride>,
    http: &reqwest::Client,
) -> Result<String, String> {
    let resp = http
        .get(url)
        .timeout(Duration::from_secs(300))
        .send()
        .await
        .map_err(|e| format!("download failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("download failed: HTTP {}", resp.status()));
    }
    let bytes = resp.bytes().await.map_err(|e| format!("download failed: {e}"))?;
    tokio::fs::write(zip_dest, &bytes)
        .await
        .map_err(|e| format!("write staging zip: {e}"))?;
    {
        let mut st = shared.inner.lock().unwrap();
        st.downloading = Some(0.5);
    }

    // Expand via PowerShell so we don't pull a zip crate for a
    // Windows-only target. Paths arrive via env — zero quoting risk.
    let ok = tokio::process::Command::new("powershell.exe")
        .arg("-NoProfile")
        .arg("-Command")
        .arg("Expand-Archive -Force -LiteralPath $env:DL_ZIP -DestinationPath $env:DL_STAGE")
        .env("DL_ZIP", zip_dest)
        .env("DL_STAGE", stage)
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !ok {
        return Err("could not unpack the downloaded package".into());
    }
    if !stage.join("doclink-win.exe").exists() {
        return Err("downloaded package is missing doclink-win.exe".into());
    }

    let appdir = app_dir();
    std::process::Command::new("powershell.exe")
        .arg("-NoProfile")
        .arg("-WindowStyle")
        .arg("Hidden")
        .arg("-Command")
        .arg(APPLY_SCRIPT)
        .env("DL_STAGE", stage)
        .env("DL_ZIP", zip_dest)
        .env("DL_APPDIR", &appdir)
        .spawn()
        .map_err(|e| format!("launch updater: {e}"))?;
    {
        let mut st = shared.inner.lock().unwrap();
        st.downloading = None;
        st.applied = true;
    }
    Ok("Update downloaded — DocLink will restart in a moment".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_parsing_and_comparison() {
        assert_eq!(parse_version("0.2.0"), Some((0, 2, 0)));
        assert_eq!(parse_version("v0.3.1"), Some((0, 3, 1)));
        assert_eq!(parse_version("1"), Some((1, 0, 0)));
        assert_eq!(parse_version("2.5"), Some((2, 5, 0)));
        assert!(parse_version("").is_none());
        assert!(parse_version("nope").is_none());

        assert!(version_gt("0.3.0", "0.2.0"));
        assert!(version_gt("1.0.0", "0.9.9"));
        assert!(version_gt("v0.9.0", "0.8.1"));
        assert!(!version_gt("0.2.0", "0.2.0"));
        assert!(!version_gt("0.1.9", "0.2.0"));
        assert!(version_gt("0.3.0", "garbage"));
    }
}