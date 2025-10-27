use crate::database::{Database, CameraScreenshot};
use crate::config::ScanConfig;
use anyhow::Result;
use chrono::Utc;
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::path::Path;
use tokio::process::Command;
use std::sync::Mutex;
use tokio::fs;
use tracing::{debug, info, warn};
use uuid::Uuid;

pub struct CameraDetector {
    screenshot_dir: String,
    config: ScanConfig,
}

impl CameraDetector {
    pub fn new(screenshot_dir: String, config: ScanConfig) -> Self {
        Self { screenshot_dir, config }
    }

    pub async fn detect_and_capture_cameras(&self, db: &Database, session_id: Uuid) -> Result<()> {
        info!("Starting camera detection and screenshot capture");
        
        // get all hosts with port 554 open
        let hosts_with_rtsp = self.get_hosts_with_rtsp_port(db, session_id).await?;
        
        if hosts_with_rtsp.is_empty() {
            info!("No hosts found with RTSP port 554 open");
            return Ok(());
        }

        info!("Found {} hosts with RTSP port 554 open", hosts_with_rtsp.len());

        fs::create_dir_all(&self.screenshot_dir).await?;

        for host_ip in hosts_with_rtsp {
            info!("Attempting to capture screenshot from camera at {}", host_ip);
            
            match self.capture_camera_screenshot(&host_ip).await {
                Ok(screenshot_path) => {
                    // info!("Successfully captured screenshot from {}: {}", host_ip, screenshot_path);
                    
                    let rtsp_url = self.get_working_rtsp_url(&host_ip)?;
                    let screenshot = CameraScreenshot {
                        id: Uuid::new_v4(),
                        scan_session_id: session_id,
                        host_ip: host_ip.clone(),
                        rtsp_url,
                        screenshot_path: screenshot_path.clone(),
                        captured_at: Utc::now(),
                        error_message: None,
                    };
                    
                    db.insert_camera_screenshot(&screenshot).await?;
                }
                Err(e) => {
                    // warn!("Failed to capture screenshot from {}: {}", host_ip, e);
                    
                    // log the failure to database
                    let screenshot = CameraScreenshot {
                        id: Uuid::new_v4(),
                        scan_session_id: session_id,
                        host_ip: host_ip.clone(),
                        rtsp_url: "N/A".to_string(),
                        screenshot_path: "N/A".to_string(),
                        captured_at: Utc::now(),
                        error_message: Some(e.to_string()),
                    };
                    
                    if let Err(db_err) = db.insert_camera_screenshot(&screenshot).await {
                        warn!("Failed to log camera error to database: {}", db_err);
                    }
                }
            }
        }

        Ok(())
    }

    async fn get_hosts_with_rtsp_port(&self, db: &Database, session_id: Uuid) -> Result<Vec<String>> {
        let hosts = db.get_hosts_by_session(&session_id).await?;
        let mut rtsp_hosts = Vec::new();

        for host in hosts {
            let ports = db.get_ports_by_host(&host.id).await?;
            let has_rtsp_port = ports.iter().any(|p| p.port_number == 554 && p.state == "open");
            
            if has_rtsp_port {
                rtsp_hosts.push(host.ip_address);
            }
        }

        Ok(rtsp_hosts)
    }

    pub async fn capture_camera_screenshot(&self, host_ip: &str) -> Result<String> {
        let rtsp_urls = self.get_rtsp_urls(host_ip);
        
        // Only try the FIRST URL to ensure exactly 1 attempt per host
        let rtsp_url = &rtsp_urls[0];
        debug!("Attempting camera capture for {} with URL: {}", host_ip, rtsp_url);

        // Attempt screenshot on the first (and only) URL
        match self.try_capture_screenshot(rtsp_url, host_ip, 0).await {
            Ok(screenshot_path) => {
                self.store_working_url(host_ip, rtsp_url);
                Ok(screenshot_path)
            }
            Err(e) => {
                // warn!("Screenshot capture failed for {}: {}", rtsp_url, e);
                Err(anyhow::anyhow!("Screenshot failed for {}: {}", host_ip, e))
            }
        }
    }

    fn get_rtsp_urls(&self, host_ip: &str) -> Vec<String> {
        vec![
            format!("rtsp://{}@{}:554/axis-media/media.amp", self.config.camera_auth, host_ip),
            format!("rtsp://{}@{}:554/axis-media/media.amp?videocodec=h264&resolution=640x480", self.config.camera_auth, host_ip),
            format!("rtsp://{}@{}:554/axis-media/media.amp", self.config.camera_auth, host_ip),
        ]
    }

    async fn try_capture_screenshot(&self, rtsp_url: &str, host_ip: &str, index: usize) -> Result<String> {
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let filename = format!("camera_{}_{}_{}.jpg", host_ip.replace(".", "_"), timestamp, index);
        let screenshot_path = Path::new(&self.screenshot_dir).join(&filename);
        
        if let Some(parent) = screenshot_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        // use ffmpeg to capture a single frame from the RTSP stream
        let mut cmd = tokio::process::Command::new("ffmpeg");
        cmd.args(&[
            "-i", rtsp_url,
            "-vframes", "1",
            "-q:v", "2",
            "-y", // overwrite
            screenshot_path.to_str().unwrap(),
        ]);

        debug!("Running ffmpeg command: {:?}", cmd);

        let output = match tokio::time::timeout(
            std::time::Duration::from_secs(6), // 6 7 67 67 67 67 67 67
            cmd.output()
        ).await {
            Ok(result) => result?,
            Err(_) => {
                return Err(anyhow::anyhow!("ffmpeg timeout after 6 seconds for URL: {}", rtsp_url));
            }
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let exit_code = output.status.code().unwrap_or(-1);
            
            // warn!("Camera capture failed for {} (URL {}):", host_ip, rtsp_url);
            // warn!("  Exit code: {}", exit_code);
            // warn!("  STDERR: {}", stderr);
            // if !stdout.is_empty() {
            //     warn!("  STDOUT: {}", stdout);
            // }
            
            return Err(anyhow::anyhow!("ffmpeg failed (exit code {}): {}", exit_code, stderr));
        }

        // verify the file was created and has content
        if !screenshot_path.exists() {
            return Err(anyhow::anyhow!("Screenshot file was not created"));
        }

        let metadata = fs::metadata(&screenshot_path).await?;
        if metadata.len() == 0 {
            return Err(anyhow::anyhow!("Screenshot file is empty"));
        }

        Ok(screenshot_path.to_string_lossy().to_string())
    }

}

// thread-safe storage for working URLs
lazy_static! {
    static ref WORKING_URLS: Mutex<HashMap<String, String>> = Mutex::new(HashMap::new());
}

impl CameraDetector {
    pub fn get_working_rtsp_url(&self, host_ip: &str) -> Result<String> {
        if let Ok(urls) = WORKING_URLS.lock() {
            if let Some(url) = urls.get(host_ip) {
                return Ok(url.clone());
            }
        }
        Err(anyhow::anyhow!("No working RTSP URL found for {}", host_ip))
    }

    fn store_working_url(&self, host_ip: &str, url: &str) {
        if let Ok(mut urls) = WORKING_URLS.lock() {
            urls.insert(host_ip.to_string(), url.to_string());
        }
    }
}
