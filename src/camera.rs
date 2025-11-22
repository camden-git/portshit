use crate::config::ScanConfig;
use crate::database::{CameraScreenshot, Database};
use anyhow::Result;
use chrono::Utc;
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use tokio::fs;
use tokio::process::Command;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// represents a discovered camera stream
#[derive(Debug, Clone)]
struct DiscoveredCamera {
    rtsp_url: String,
    camera_index: Option<i32>,
    camera_type: String,
}

/// result of testing an RTSP URL
#[derive(Debug, Clone, PartialEq)]
enum RtspTestResult {
    /// camera stream is accessible
    Accessible,
    /// HTTP 401 Unauthorized or 400 Bad Request - end of available cameras
    EndOfCameras,
    /// other error
    Error(String),
}

pub struct CameraDetector {
    screenshot_dir: String,
    config: ScanConfig,
}

impl CameraDetector {
    pub fn new(screenshot_dir: String, config: ScanConfig) -> Self {
        Self {
            screenshot_dir,
            config,
        }
    }

    pub async fn detect_and_capture_cameras(&self, db: &Database, session_id: Uuid) -> Result<()> {
        info!("Starting camera detection and screenshot capture");

        // get all hosts with port 554 open
        let hosts_with_rtsp = self.get_hosts_with_rtsp_port(db, session_id).await?;

        if hosts_with_rtsp.is_empty() {
            info!("No hosts found with RTSP port 554 open");
            return Ok(());
        }

        info!(
            "Found {} hosts with RTSP port 554 open",
            hosts_with_rtsp.len()
        );

        fs::create_dir_all(&self.screenshot_dir).await?;

        for host_ip in hosts_with_rtsp {
            info!(
                "Discovering and capturing cameras from host {}",
                host_ip
            );

            let discovered_cameras = self.discover_multi_camera_system(&host_ip).await?;

            if discovered_cameras.is_empty() {
                warn!("No cameras discovered for host {}", host_ip);
                let screenshot = CameraScreenshot {
                    id: Uuid::new_v4(),
                    scan_session_id: session_id,
                    host_ip: host_ip.clone(),
                    rtsp_url: "N/A".to_string(),
                    screenshot_path: "N/A".to_string(),
                    captured_at: Utc::now(),
                    error_message: Some("No cameras discovered".to_string()),
                    camera_index: None,
                    camera_type: None,
                };

                if let Err(db_err) = db.insert_camera_screenshot(&screenshot).await {
                    warn!("Failed to log camera error to database: {}", db_err);
                }
                continue;
            }

            info!(
                "Discovered {} cameras for host {}",
                discovered_cameras.len(),
                host_ip
            );

            // capture screenshots
            for (idx, camera) in discovered_cameras.iter().enumerate() {
                // check if we already have this camera URL
                if db
                    .has_camera_screenshot_for_url(&session_id, &host_ip, &camera.rtsp_url)
                    .await
                    .unwrap_or(false)
                {
                    debug!(
                        "Skipping {} - already captured for session",
                        camera.rtsp_url
                    );
                    continue;
                }

                match self
                    .try_capture_screenshot(&camera.rtsp_url, &host_ip, idx)
                    .await
                {
                    Ok(screenshot_path) => {
                        let screenshot = CameraScreenshot {
                            id: Uuid::new_v4(),
                            scan_session_id: session_id,
                            host_ip: host_ip.clone(),
                            rtsp_url: camera.rtsp_url.clone(),
                            screenshot_path: screenshot_path.clone(),
                            captured_at: Utc::now(),
                            error_message: None,
                            camera_index: camera.camera_index,
                            camera_type: Some(camera.camera_type.clone()),
                        };

                        if let Err(e) = db.insert_camera_screenshot(&screenshot).await {
                            warn!(
                                "Failed to save camera screenshot to database: {}",
                                e
                            );
                        } else {
                            debug!(
                                "Successfully saved camera {} (type: {}) for host {}",
                                camera.camera_index.map(|i| i.to_string()).unwrap_or_else(|| "default".to_string()),
                                camera.camera_type,
                                host_ip
                            );
                        }
                    }
                    Err(e) => {
                        warn!(
                            "Failed to capture screenshot from {} (URL: {}): {}",
                            host_ip, camera.rtsp_url, e
                        );

                        let screenshot = CameraScreenshot {
                            id: Uuid::new_v4(),
                            scan_session_id: session_id,
                            host_ip: host_ip.clone(),
                            rtsp_url: camera.rtsp_url.clone(),
                            screenshot_path: "N/A".to_string(),
                            captured_at: Utc::now(),
                            error_message: Some(e.to_string()),
                            camera_index: camera.camera_index,
                            camera_type: Some(camera.camera_type.clone()),
                        };

                        if let Err(db_err) = db.insert_camera_screenshot(&screenshot).await {
                            warn!("Failed to log camera error to database: {}", db_err);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn get_hosts_with_rtsp_port(
        &self,
        db: &Database,
        session_id: Uuid,
    ) -> Result<Vec<String>> {
        let hosts = db.get_hosts_by_session(&session_id).await?;
        let mut rtsp_hosts = Vec::new();

        for host in hosts {
            let ports = db.get_ports_by_host(&host.id).await?;
            let has_rtsp_port = ports
                .iter()
                .any(|p| p.port_number == 554 && p.state == "open");

            if has_rtsp_port {
                rtsp_hosts.push(host.ip_address);
            }
        }

        Ok(rtsp_hosts)
    }

    /// discovers and captures all cameras for a single host
    /// returns the number of cameras successfully captured
    pub async fn discover_and_capture_cameras_for_host(
        &self,
        db: &Database,
        session_id: Uuid,
        host_ip: &str,
    ) -> Result<usize> {
        let discovered_cameras = self.discover_multi_camera_system(host_ip).await?;

        if discovered_cameras.is_empty() {
            warn!("No cameras discovered for host {}", host_ip);
            let screenshot = CameraScreenshot {
                id: Uuid::new_v4(),
                scan_session_id: session_id,
                host_ip: host_ip.to_string(),
                rtsp_url: "N/A".to_string(),
                screenshot_path: "N/A".to_string(),
                captured_at: Utc::now(),
                error_message: Some("No cameras discovered".to_string()),
                camera_index: None,
                camera_type: None,
            };

            if let Err(db_err) = db.insert_camera_screenshot(&screenshot).await {
                warn!("Failed to log camera error to database: {}", db_err);
            }
            return Ok(0);
        }

        info!(
            "Discovered {} cameras for host {}",
            discovered_cameras.len(),
            host_ip
        );

        // capture screenshots for each discovered camera
        let mut captured_count = 0;
        for (idx, camera) in discovered_cameras.iter().enumerate() {
            // check if we already have this camera URL
            if db
                .has_camera_screenshot_for_url(&session_id, host_ip, &camera.rtsp_url)
                .await
                .unwrap_or(false)
            {
                debug!(
                    "Skipping {} - already captured for session",
                    camera.rtsp_url
                );
                continue;
            }

            match self
                .try_capture_screenshot(&camera.rtsp_url, host_ip, idx)
                .await
            {
                Ok(screenshot_path) => {
                    let screenshot = CameraScreenshot {
                        id: Uuid::new_v4(),
                        scan_session_id: session_id,
                        host_ip: host_ip.to_string(),
                        rtsp_url: camera.rtsp_url.clone(),
                        screenshot_path: screenshot_path.clone(),
                        captured_at: Utc::now(),
                        error_message: None,
                        camera_index: camera.camera_index,
                        camera_type: Some(camera.camera_type.clone()),
                    };

                    if let Err(e) = db.insert_camera_screenshot(&screenshot).await {
                        warn!(
                            "Failed to save camera screenshot to database: {}",
                            e
                        );
                    } else {
                        captured_count += 1;
                        debug!(
                            "Successfully saved camera {} (type: {}) for host {}",
                            camera
                                .camera_index
                                .map(|i| i.to_string())
                                .unwrap_or_else(|| "default".to_string()),
                            camera.camera_type,
                            host_ip
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to capture screenshot from {} (URL: {}): {}",
                        host_ip, camera.rtsp_url, e
                    );

                    let screenshot = CameraScreenshot {
                        id: Uuid::new_v4(),
                        scan_session_id: session_id,
                        host_ip: host_ip.to_string(),
                        rtsp_url: camera.rtsp_url.clone(),
                        screenshot_path: "N/A".to_string(),
                        captured_at: Utc::now(),
                        error_message: Some(e.to_string()),
                        camera_index: camera.camera_index,
                        camera_type: Some(camera.camera_type.clone()),
                    };

                    if let Err(db_err) = db.insert_camera_screenshot(&screenshot).await {
                        warn!("Failed to log camera error to database: {}", db_err);
                    }
                }
            }
        }

        Ok(captured_count)
    }

    /// Captures a screenshot from a camera
    /// This method discovers cameras and captures the first available one
    pub async fn capture_camera_screenshot(&self, host_ip: &str) -> Result<String> {
        let discovered_cameras = self.discover_multi_camera_system(host_ip).await?;

        if discovered_cameras.is_empty() {
            return Err(anyhow::anyhow!("No cameras discovered for {}", host_ip));
        }

        // use the first discovered camera
        let camera = &discovered_cameras[0];
        debug!(
            "Attempting camera capture for {} with URL: {}",
            host_ip, camera.rtsp_url
        );

        match self
            .try_capture_screenshot(&camera.rtsp_url, host_ip, 0)
            .await
        {
            Ok(screenshot_path) => {
                self.store_working_url(host_ip, &camera.rtsp_url);
                Ok(screenshot_path)
            }
            Err(e) => {
                Err(anyhow::anyhow!("Screenshot failed for {}: {}", host_ip, e))
            }
        }
    }

    fn get_rtsp_urls(&self, host_ip: &str) -> Vec<String> {
        vec![
            format!(
                "rtsp://{}@{}:554/axis-media/media.amp",
                self.config.camera_auth, host_ip
            ),
            format!(
                "rtsp://{}@{}:554/axis-media/media.amp?videocodec=h264&resolution=640x480",
                self.config.camera_auth, host_ip
            ),
            format!(
                "rtsp://{}@{}:554/axis-media/media.amp",
                self.config.camera_auth, host_ip
            ),
        ]
    }

    /// builds an RTSP URL with camera parameter
    fn build_rtsp_url_with_camera(&self, host_ip: &str, camera_index: Option<i32>) -> String {
        if let Some(idx) = camera_index {
            format!(
                "rtsp://{}@{}:554/axis-media/media.amp?camera={}",
                self.config.camera_auth, host_ip, idx
            )
        } else {
            format!(
                "rtsp://{}@{}:554/axis-media/media.amp",
                self.config.camera_auth, host_ip
            )
        }
    }

    async fn test_rtsp_url(&self, rtsp_url: &str) -> RtspTestResult {
        let mut cmd = tokio::process::Command::new("ffmpeg");
        cmd.args(&[
            "-rtsp_transport",
            "tcp",
            "-i",
            rtsp_url,
            "-vframes",
            "1",
            "-f",
            "null",
            "-",
        ]);

        let output = match tokio::time::timeout(std::time::Duration::from_secs(3), cmd.output()).await {
            Ok(Ok(output)) => output,
            Ok(Err(e)) => {
                return RtspTestResult::Error(format!("Command execution error: {}", e));
            }
            Err(_) => {
                return RtspTestResult::Error("Timeout after 3 seconds".to_string());
            }
        };

        if output.status.success() {
            return RtspTestResult::Accessible;
        }

        // check stderr for HTTP 401 or 400 errors
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr_lower = stderr.to_lowercase();

        // check for HTTP 401 Unauthorized or 400 Bad Request
        if stderr_lower.contains("401") || stderr_lower.contains("unauthorized") {
            return RtspTestResult::EndOfCameras;
        }
        if stderr_lower.contains("400") || stderr_lower.contains("bad request") {
            return RtspTestResult::EndOfCameras;
        }

        // other error
        RtspTestResult::Error(stderr.to_string())
    }

    /// Discovers all cameras
    /// Returns a list of discovered cameras
    /// Stops when reached the end of available cameras
    async fn discover_multi_camera_system(
        &self,
        host_ip: &str,
    ) -> Result<Vec<DiscoveredCamera>> {
        let mut discovered = Vec::new();

        // test the default URL
        let default_url = self.build_rtsp_url_with_camera(host_ip, None);
        match self.test_rtsp_url(&default_url).await {
            RtspTestResult::Accessible => {
                discovered.push(DiscoveredCamera {
                    rtsp_url: default_url,
                    camera_index: None,
                    camera_type: "default".to_string(),
                });
                debug!("Found default camera for {}", host_ip);
            }
            RtspTestResult::EndOfCameras => {
                // if default URL returns 401/400, this camera doesn't support multi-camera system
                debug!("Default URL returned 401/400 for {}, likely not a multi-camera system", host_ip);
            }
            RtspTestResult::Error(e) => {
                debug!("Error testing default URL for {}: {}", host_ip, e);
            }
        }

        // test cameras sequentially
        // continue until we get a 401 or 400 error, which indicates we've reached the end
        let mut camera_idx = 1;
        let mut found_individual = false;
        let mut found_grid = false;
        let max_cameras_to_test = 10; // safety limit to prevent infinite loops

        while camera_idx <= max_cameras_to_test {
            let url = self.build_rtsp_url_with_camera(host_ip, Some(camera_idx));
            match self.test_rtsp_url(&url).await {
                RtspTestResult::Accessible => {
                    // determine if this is likely a grid view or individual camera
                    // grid view is typically after all individual cameras
                    // we'll mark it as grid if we've already found individual cameras
                    let is_grid = found_individual && !found_grid;
                    let camera_type = if is_grid {
                        "grid".to_string()
                    } else {
                        "individual".to_string()
                    };

                    if is_grid {
                        found_grid = true;
                    } else {
                        found_individual = true;
                    }

                    discovered.push(DiscoveredCamera {
                        rtsp_url: url,
                        camera_index: Some(camera_idx),
                        camera_type: camera_type.clone(),
                    });
                    debug!(
                        "Found {} camera {} for {}",
                        if is_grid { "grid" } else { "individual" },
                        camera_idx,
                        host_ip
                    );
                    camera_idx += 1;
                }
                RtspTestResult::EndOfCameras => {
                    // 401 or 400 error - reached the end of available cameras
                    debug!(
                        "Reached end of cameras for {} at camera={} (401/400 error)",
                        host_ip, camera_idx
                    );
                    break;
                }
                RtspTestResult::Error(e) => {
                    // other error - log it but continue testing
                    // could be a network issue or the camera might be temporarily unavailable
                    debug!(
                        "Error testing camera {} for {}: {}",
                        camera_idx, host_ip, e
                    );
                    camera_idx += 1;
                }
            }
        }

        // if we only found the default camera, return just that
        // otherwise, return all discovered cameras (excluding default if we have individual cameras)
        let has_individual = discovered.iter().any(|c| c.camera_index.is_some());
        if has_individual {
            // filter out default camera if we have individual cameras
            Ok(discovered
                .into_iter()
                .filter(|c| c.camera_index.is_some())
                .collect())
        } else {
            // only default camera found, return it
            Ok(discovered)
        }
    }

    async fn try_capture_screenshot(
        &self,
        rtsp_url: &str,
        host_ip: &str,
        index: usize,
    ) -> Result<String> {
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let filename = format!(
            "camera_{}_{}_{}.jpg",
            host_ip.replace(".", "_"),
            timestamp,
            index
        );
        let screenshot_path = Path::new(&self.screenshot_dir).join(&filename);

        if let Some(parent) = screenshot_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        // use ffmpeg to capture a single frame from the RTSP stream
        let mut cmd = tokio::process::Command::new("ffmpeg");
        cmd.args(&[
            "-i",
            rtsp_url,
            "-vframes",
            "1",
            "-q:v",
            "2",
            "-y", // overwrite
            screenshot_path.to_str().unwrap(),
        ]);

        debug!("Running ffmpeg command: {:?}", cmd);

        let output = match tokio::time::timeout(
            std::time::Duration::from_secs(6), // 6 7 67 67 67 67 67 67
            cmd.output(),
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => {
                return Err(anyhow::anyhow!(
                    "ffmpeg timeout after 6 seconds for URL: {}",
                    rtsp_url
                ));
            }
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let _stdout = String::from_utf8_lossy(&output.stdout);
            let exit_code = output.status.code().unwrap_or(-1);

            // warn!("Camera capture failed for {} (URL {}):", host_ip, rtsp_url);
            // warn!("  Exit code: {}", exit_code);
            // warn!("  STDERR: {}", stderr);
            // if !stdout.is_empty() {
            //     warn!("  STDOUT: {}", stdout);
            // }

            return Err(anyhow::anyhow!(
                "ffmpeg failed (exit code {}): {}",
                exit_code,
                stderr
            ));
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
