use crate::config::ScanConfig;
use crate::database::{Database, Host};
use crate::network::NetworkRange;
use crate::nmap::NmapScanner;
use crate::zmap::{ZmapConfig, ZmapScanner};
use anyhow::Result;
use chrono::Utc;
use std::sync::Arc;
use tokio::sync::{mpsc, Semaphore};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct PipelineConfig {
    pub discovery_threads: usize,
    pub service_threads: usize,
    pub camera_threads: usize,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            discovery_threads: 4,
            service_threads: 2,
            camera_threads: 2,
        }
    }
}

#[derive(Debug)]
pub struct PipelineScanner {
    config: ScanConfig,
    pipeline_config: PipelineConfig,
    chunk_size: u8,
}

impl PipelineScanner {
    pub fn new(config: ScanConfig) -> Self {
        Self {
            pipeline_config: PipelineConfig::default(),
            chunk_size: 23, // Default to /23 chunks
            config,
        }
    }

    pub fn with_pipeline_config(mut self, pipeline_config: PipelineConfig) -> Self {
        self.pipeline_config = pipeline_config;
        self
    }

    pub fn with_chunk_size(mut self, chunk_size: u8) -> Self {
        self.chunk_size = chunk_size;
        self
    }

    pub async fn scan_large_network(&self, db: &Database) -> Result<Uuid> {
        let (session_id, is_resume) = if let Some(resume_session_str) = &self.config.resume_session {
            let resume_session_id = Uuid::parse_str(resume_session_str)
                .map_err(|e| anyhow::anyhow!("Invalid resume session ID: {}", e))?;
            info!("Resuming scan session: {}", resume_session_id);
            (resume_session_id, true)
        } else {
            (Uuid::new_v4(), false)
        };
        
        let start_time = Utc::now();
        
        if is_resume {
            info!("Resuming 3-stage pipeline scan of large network: {}", self.config.target_range);
        } else {
            info!("Starting 3-stage pipeline scan of large network: {}", self.config.target_range);
        }
        
        // parse the target range
        let network_range = NetworkRange::from_range(&self.config.target_range)?;
        let total_hosts = network_range.get_host_count();
        
        info!("Network range: {} ({} hosts)", network_range.to_cidr_string(), total_hosts);
        
        // split into manageable chunks
        let chunks = network_range.split_into_chunks(self.chunk_size)?;
        let total_chunks = chunks.len();
        info!("Split into {} chunks of /{}", total_chunks, self.chunk_size);
        
        if chunks.is_empty() {
            return Err(anyhow::anyhow!("No chunks to scan"));
        }

        // create database session
        let session = crate::database::ScanSession {
            id: session_id,
            target_range: format!("{} ({} chunks)", self.config.target_range, total_chunks),
            start_time,
            end_time: None,
            total_hosts: 0,
            hosts_up: 0,
            hosts_down: 0,
            config_json: serde_json::to_string(&self.config)?,
        };
        
        if !is_resume {
            db.create_scan_session(&session).await?;
        }

        // filter out completed chunks if resuming
        let chunks_to_process = if is_resume {
            let completed_discovery = db.get_completed_chunks_for_stage(&session_id, "discovery").await?;
            let completed_service = db.get_completed_chunks_for_stage(&session_id, "service").await?;
            let completed_camera = db.get_completed_chunks_for_stage(&session_id, "camera").await?;
            
            info!("Resume status - Discovery: {} completed, Service: {} completed, Camera: {} completed", 
                  completed_discovery.len(), completed_service.len(), completed_camera.len());
            
            // for resume, we need to process chunks that haven't completed all stages
            chunks.into_iter().filter(|chunk| {
                let chunk_str = chunk.to_cidr_string();
                !completed_camera.contains(&chunk_str) // only skip if camera stage is complete
            }).collect()
        } else {
            chunks
        };

        info!("Processing {} chunks ({} total)", chunks_to_process.len(), total_chunks);

        // create channels for inter-stage communication
        let (discovery_tx, discovery_rx) = mpsc::channel::<NetworkRange>(chunks_to_process.len());
        let (service_tx, service_rx) = mpsc::channel::<Vec<Host>>(chunks_to_process.len());
        let (camera_tx, camera_rx) = mpsc::channel::<Vec<Host>>(chunks_to_process.len());
        let (progress_tx, mut progress_rx) = mpsc::channel::<String>(chunks_to_process.len() * 3);

        // create semaphores for each stage
        let discovery_semaphore = Arc::new(Semaphore::new(self.pipeline_config.discovery_threads));
        let service_semaphore = Arc::new(Semaphore::new(self.pipeline_config.service_threads));
        let camera_semaphore = Arc::new(Semaphore::new(self.pipeline_config.camera_threads));
        let db_arc = Arc::new(db.clone());

        let chunks_to_process_count = chunks_to_process.len();
        
        // spawn progress reporter
        let progress_handle = tokio::spawn(async move {
            let mut completed = 0;
            let total = chunks_to_process_count * 3; // 3 stages per chunk
            
            while let Some(message) = progress_rx.recv().await {
                completed += 1;
                info!("Pipeline Progress: {}/{} - {}", completed, total, message);
            }
        });

        // discovery threads
        let discovery_rx_arc = Arc::new(tokio::sync::Mutex::new(discovery_rx));
        let mut discovery_handles = Vec::new();
        for i in 0..self.pipeline_config.discovery_threads {
            let discovery_semaphore_clone = discovery_semaphore.clone();
            let service_tx_clone = service_tx.clone();
            let progress_tx_clone = progress_tx.clone();
            let db_clone = db_arc.clone();
            let session_id_clone = session_id;
            let config_clone = self.config.clone();
            let discovery_rx_clone = discovery_rx_arc.clone();

            let handle = tokio::spawn(async move {
                loop {
                    let chunk = {
                        let mut rx = discovery_rx_clone.lock().await;
                        match rx.recv().await {
                            Some(chunk) => chunk,
                            None => break, // Channel closed
                        }
                    };
                    
                    let _permit = discovery_semaphore_clone.acquire().await.unwrap();
                    
                    debug!("Discovery thread {} processing chunk: {}", i, chunk.to_cidr_string());
                    
                    match Self::discovery_stage(&config_clone, &db_clone, session_id_clone, &chunk).await {
                        Ok(hosts) => {
                            let message = format!("[DISCOVERY] {}: {} hosts found", 
                                chunk.to_cidr_string(), hosts.len());
                            progress_tx_clone.send(message).await.ok();
                            
                            if !hosts.is_empty() {
                                service_tx_clone.send(hosts).await.ok();
                            }
                        }
                        Err(e) => {
                            let message = format!("[DISCOVERY] {}: FAILED - {}", chunk.to_cidr_string(), e);
                            warn!("{}", message);
                            progress_tx_clone.send(message).await.ok();
                        }
                    }
                }
            });
            
            discovery_handles.push(handle);
        }

        // service detection threads
        let service_rx_arc = Arc::new(tokio::sync::Mutex::new(service_rx));
        let mut service_handles = Vec::new();
        for i in 0..self.pipeline_config.service_threads {
            let service_semaphore_clone = service_semaphore.clone();
            let camera_tx_clone = camera_tx.clone();
            let progress_tx_clone = progress_tx.clone();
            let db_clone = db_arc.clone();
            let config_clone = self.config.clone();
            let service_rx_clone = service_rx_arc.clone();
            let session_id_clone = session_id;

            let handle = tokio::spawn(async move {
                loop {
                    let hosts = {
                        let mut rx = service_rx_clone.lock().await;
                        match rx.recv().await {
                            Some(hosts) => hosts,
                            None => break, // Channel closed
                        }
                    };
                    
                    let _permit = service_semaphore_clone.acquire().await.unwrap();
                    
                    debug!("Service thread {} processing {} hosts", i, hosts.len());
                    
                    match Self::service_stage(&config_clone, &db_clone, session_id_clone, "unknown", &hosts).await {
                        Ok(updated_hosts) => {
                            let message = format!("[SERVICE] {} hosts processed", updated_hosts.len());
                            progress_tx_clone.send(message).await.ok();
                            
                            // stream hosts to camera stage only if scanning port 554
                            if config_clone.port_range.contains("554") {
                                debug!("[SERVICE] Streaming {} hosts to camera stage", updated_hosts.len());
                                camera_tx_clone.send(updated_hosts).await.ok();
                            } else {
                                debug!("[SERVICE] Skipping camera stage - port 554 not in scan range");
                            }
                        }
                        Err(e) => {
                            let message = format!("[SERVICE] FAILED - {}", e);
                            warn!("{}", message);
                            progress_tx_clone.send(message).await.ok();
                        }
                    }
                }
            });
            
            service_handles.push(handle);
        }

        // camera capture threads
        let camera_rx_arc = Arc::new(tokio::sync::Mutex::new(camera_rx));
        let mut camera_handles = Vec::new();
        
        // skip camera threads entirely if not scanning port 554
        if self.config.port_range.contains("554") {
            info!("Starting {} camera capture threads", self.pipeline_config.camera_threads);
            for i in 0..self.pipeline_config.camera_threads {
            let camera_semaphore_clone = camera_semaphore.clone();
            let progress_tx_clone = progress_tx.clone();
            let session_id_clone = session_id;
            let camera_rx_clone = camera_rx_arc.clone();
            let db_clone = db_arc.clone();
            let config_clone = self.config.clone();

            let handle = tokio::spawn(async move {
                loop {
                    let hosts = {
                        let mut rx = camera_rx_clone.lock().await;
                        match rx.recv().await {
                            Some(hosts) => hosts,
                            None => break, // Channel closed
                        }
                    };
                    
                    let _permit = camera_semaphore_clone.acquire().await.unwrap();
                    
                    debug!("Camera thread {} processing {} hosts", i, hosts.len());
                    
                    match Self::camera_stage(&config_clone, &db_clone, session_id_clone, "unknown", &hosts).await {
                        Ok(screenshots) => {
                            let message = format!("[CAMERA] {} screenshots captured", screenshots);
                            progress_tx_clone.send(message).await.ok();
                        }
                        Err(e) => {
                            let message = format!("[CAMERA] FAILED - {}", e);
                            warn!("{}", message);
                            progress_tx_clone.send(message).await.ok();
                        }
                    }
                }
            });
            
            camera_handles.push(handle);
            }
        } else {
            info!("Skipping camera capture threads - port 554 not in scan range");
        }

        // send all chunks to discovery stage
        for chunk in chunks_to_process {
            discovery_tx.send(chunk).await.ok();
        }

        // close discovery channel to signal completion
        drop(discovery_tx);

        // close service and camera channels to signal completion
        drop(service_tx);
        drop(camera_tx);

        // wait for all stages to complete concurrently
        let (discovery_result, service_result, camera_result) = tokio::join!(
            async {
                let mut results = Vec::new();
                for handle in discovery_handles {
                    if let Err(e) = handle.await {
                        results.push(Err(e));
                    }
                }
                if results.is_empty() { Ok(()) } else { results.into_iter().next().unwrap() }
            },
            async {
                let mut results = Vec::new();
                for handle in service_handles {
                    if let Err(e) = handle.await {
                        results.push(Err(e));
                    }
                }
                if results.is_empty() { Ok(()) } else { results.into_iter().next().unwrap() }
            },
            async {
                let mut results = Vec::new();
                for handle in camera_handles {
                    if let Err(e) = handle.await {
                        results.push(Err(e));
                    }
                }
                if results.is_empty() { Ok(()) } else { results.into_iter().next().unwrap() }
            }
        );

        // check for errors
        discovery_result?;
        service_result?;
        camera_result?;

        // close progress channel and wait for reporter
        drop(progress_tx);
        progress_handle.await.ok();

        // update session with final results
        let mut updated_session = session;
        updated_session.end_time = Some(Utc::now());
        // TODO: get actual counts from database
        updated_session.total_hosts = 0;
        updated_session.hosts_up = 0;
        updated_session.hosts_down = 0;

        db.update_scan_session(&updated_session).await?;

        info!("3-stage pipeline scan completed successfully!");

        Ok(session_id)
    }

    async fn discovery_stage(
        config: &ScanConfig,
        db: &Database,
        session_id: Uuid,
        chunk: &NetworkRange,
    ) -> Result<Vec<Host>> {
        let progress_id = if !config.turbo_mode {
            db.create_scan_progress(&session_id, &chunk.to_cidr_string(), "discovery").await?
        } else {
            Uuid::new_v4() // dummy ID
        };
        
        let mut chunk_config = config.clone();
        chunk_config.target_range = chunk.to_cidr_string();
        chunk_config.max_concurrent_scans = 1;

        let nmap_scanner = NmapScanner::new(chunk_config);
        let hosts_found = nmap_scanner.scan_network_with_session(db, session_id).await?;
        
        // get the hosts that were discovered and restrict to this chunk's IP range
        let all_hosts = db.get_hosts_by_session(&session_id).await?;
        let hosts: Vec<Host> = all_hosts
            .into_iter()
            .filter(|h| {
                if let (std::net::IpAddr::V4(start), std::net::IpAddr::V4(end)) = (chunk.start_ip, chunk.end_ip) {
                    if let Ok(ipv4) = h.ip_address.parse::<std::net::Ipv4Addr>() {
                        let ip = u32::from(ipv4);
                        let start_u32 = u32::from(start);
                        let end_u32 = u32::from(end);
                        return ip >= start_u32 && ip <= end_u32;
                    }
                }
                false
            })
            .collect();
        
        // update progress as completed
        if !config.turbo_mode {
            db.update_scan_progress_status(&progress_id, "completed", None).await?;
        }
        
        Ok(hosts)
    }

    async fn service_stage(
        config: &ScanConfig,
        db: &Database,
        session_id: Uuid,
        chunk_range: &str,
        hosts: &[Host],
    ) -> Result<Vec<Host>> {
        // create progress record
        let progress_id = db.create_scan_progress(&session_id, chunk_range, "service").await?;
        
        if hosts.is_empty() {
            db.update_scan_progress_status(&progress_id, "completed", None).await?;
            return Ok(hosts.to_vec());
        }
        
        // perform service detection on the hosts using nmap
        let mut service_config = config.clone();
        
        // create a target list from the discovered hosts
        let host_ips: Vec<String> = hosts.iter().map(|h| h.ip_address.clone()).collect();
        let target_list = host_ips.join(",");
        service_config.target_range = target_list;
        
        // disable host discovery since we already know these hosts are up
        service_config.skip_non_pingable = true;
        
        // create a temporary nmap scanner for service detection
        let nmap_scanner = NmapScanner::new(service_config);
        
        // run service detection scan
        match nmap_scanner.scan_network_with_session(db, session_id).await {
            Ok(_) => {
                debug!("[SERVICE] Successfully completed service detection for {} hosts", hosts.len());
            }
            Err(e) => {
                warn!("[SERVICE] Service detection failed: {}", e);
                // continue anyway
            }
        }
        
        // pass through the same hosts for downstream processing (service info is stored in DB)
        let updated_hosts: Vec<Host> = hosts.to_vec();
        
        // update progress as completed
        db.update_scan_progress_status(&progress_id, "completed", None).await?;
        
        Ok(updated_hosts)
    }

    async fn camera_stage(
        config: &ScanConfig,
        db: &Database,
        session_id: Uuid,
        chunk_range: &str,
        hosts: &[Host],
    ) -> Result<usize> {
        // create progress record
        let progress_id = db.create_scan_progress(&session_id, chunk_range, "camera").await?;
        use crate::camera::CameraDetector;
        
        // create camera detector
        let screenshot_dir = format!("screenshots/{}", session_id);
        let camera_detector = CameraDetector::new(screenshot_dir, config.clone());
        
        // if we're not scanning port 554, skip camera processing entirely
        if !config.port_range.contains("554") {
            debug!("[CAMERA] Port 554 not in scan range, skipping camera processing");
            return Ok(0);
        }

        // get all ports for all hosts at once instead of per-host queries
        let host_ids: Vec<String> = hosts.iter().map(|h| h.id.to_string()).collect();
        let rtsp_ports = match db.get_ports_by_session_and_port(&session_id, 554).await {
            Ok(ports) => ports,
            Err(e) => {
                warn!("Failed to get RTSP ports: {}", e);
                return Ok(0);
            }
        };

        // filter hosts that have port 554 open
        let mut rtsp_hosts = Vec::new();
        for host in hosts {
            let has_rtsp = rtsp_ports.iter().any(|port| 
                port.host_id == host.id && (port.state == "open" || port.state == "filtered")
            );
            if has_rtsp {
                debug!("[CAMERA] Host {} has RTSP port 554", host.ip_address);
                rtsp_hosts.push(host.ip_address.clone());
            }
        }
        
        if rtsp_hosts.is_empty() {
            return Ok(0);
        }
        
        // capture screenshots from each RTSP host, skipping already captured hosts
        let mut screenshots_captured = 0;
        use std::collections::HashSet;
        let mut seen: HashSet<String> = HashSet::new();
        for host_ip in rtsp_hosts {
            if !seen.insert(host_ip.clone()) {
                continue;
            }
            if db.has_camera_screenshot_for_host(&session_id, &host_ip).await.unwrap_or(false) {
                debug!("[CAMERA] Skipping {} - screenshot already exists for session", host_ip);
                continue;
            }
            match camera_detector.capture_camera_screenshot(&host_ip).await {
                Ok(screenshot_path) => {
                    screenshots_captured += 1;
                    debug!("Successfully captured screenshot from {}: {}", host_ip, screenshot_path);
                    
                    // save screenshot info to database
                    let rtsp_url = camera_detector.get_working_rtsp_url(&host_ip)?;
                    let screenshot = crate::database::CameraScreenshot {
                        id: uuid::Uuid::new_v4(),
                        scan_session_id: session_id,
                        host_ip: host_ip.clone(),
                        rtsp_url,
                        screenshot_path: screenshot_path.clone(),
                        captured_at: chrono::Utc::now(),
                        error_message: None,
                    };
                    
                    if let Err(e) = db.insert_camera_screenshot(&screenshot).await {
                        warn!("Failed to save screenshot record to database: {}", e);
                    }
                }
                Err(e) => {
                    warn!("Failed to capture screenshot from {}: {}", host_ip, e);
                    
                    // log the failure to database
                    let screenshot = crate::database::CameraScreenshot {
                        id: uuid::Uuid::new_v4(),
                        scan_session_id: session_id,
                        host_ip: host_ip.clone(),
                        rtsp_url: "N/A".to_string(), // no working URL found
                        screenshot_path: "N/A".to_string(), // no screenshot captured
                        captured_at: chrono::Utc::now(),
                        error_message: Some(e.to_string()), // store the error message
                    };
                    
                    if let Err(db_err) = db.insert_camera_screenshot(&screenshot).await {
                        warn!("Failed to log camera error to database: {}", db_err);
                    }
                }
            }
        }
        
        // update progress as completed
        db.update_scan_progress_status(&progress_id, "completed", None).await?;
        
        Ok(screenshots_captured)
    }
}
