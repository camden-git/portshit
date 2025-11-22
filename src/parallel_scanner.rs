use crate::config::ScanConfig;
use crate::database::Database;
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
pub struct ChunkScanResult {
    pub chunk_range: String,
    pub hosts_found: u32,
    pub scan_duration: u64,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug)]
pub struct ParallelScanManager {
    config: ScanConfig,
    max_concurrent_chunks: usize,
    chunk_size: u8, // CIDR size for chunks
}

impl ParallelScanManager {
    pub fn new(config: ScanConfig) -> Self {
        Self {
            max_concurrent_chunks: config.max_concurrent_scans,
            chunk_size: 23,
            config,
        }
    }

    pub fn with_chunk_size(mut self, chunk_size: u8) -> Self {
        self.chunk_size = chunk_size;
        self
    }

    pub async fn scan_large_network(&self, db: &Database) -> Result<Uuid> {
        let session_id = Uuid::new_v4();
        let start_time = Utc::now();

        info!("Starting parallel scan: {}", self.config.target_range);

        // parse the target range
        let network_range = NetworkRange::from_range(&self.config.target_range)?;
        let total_hosts = network_range.get_host_count();

        info!(
            "Network range: {} ({} hosts)",
            network_range.to_cidr_string(),
            total_hosts
        );

        // split into manageable chunks
        let chunks = network_range.split_into_chunks(self.chunk_size)?;
        info!("Split into {} chunks of /{}", chunks.len(), self.chunk_size);

        if chunks.is_empty() {
            return Err(anyhow::anyhow!("No chunks to scan"));
        }

        // create database session
        let session = crate::database::ScanSession {
            id: session_id,
            target_range: format!("{} ({} chunks)", self.config.target_range, chunks.len()),
            start_time,
            end_time: None,
            total_hosts: 0,
            hosts_up: 0,
            hosts_down: 0,
            config_json: serde_json::to_string(&self.config)?,
        };

        db.create_scan_session(&session).await?;

        // create channels for communication
        let (result_tx, mut result_rx) = mpsc::channel::<ChunkScanResult>(chunks.len());
        let (progress_tx, mut progress_rx) = mpsc::channel::<String>(chunks.len());

        // create semaphore for limiting concurrent scans
        let semaphore = Arc::new(Semaphore::new(self.max_concurrent_chunks));
        let db_arc = Arc::new(db.clone());

        let total_chunks = chunks.len();

        // spawn progress reporter
        let progress_handle = tokio::spawn(async move {
            let mut completed = 0;

            while let Some(message) = progress_rx.recv().await {
                completed += 1;
                info!(
                    "Progress: {}/{} chunks completed - {}",
                    completed, total_chunks, message
                );
            }
        });

        // spawn chunk scanning tasks
        let mut handles = Vec::new();
        for (index, chunk) in chunks.iter().enumerate() {
            let chunk_config = self.create_chunk_config(chunk)?;
            let chunk_range = chunk.to_cidr_string();
            let semaphore_clone = semaphore.clone();
            let db_task_clone = db_arc.clone();
            let result_tx_clone = result_tx.clone();
            let progress_tx_clone = progress_tx.clone();
            let session_id_clone = session_id;

            let handle = tokio::spawn(async move {
                let _permit = semaphore_clone.acquire().await.unwrap();
                let chunk_start = Utc::now();

                debug!("Starting scan of chunk {}: {}", index + 1, chunk_range);

                let result = Self::scan_chunk(
                    &chunk_config,
                    db_task_clone.as_ref(),
                    session_id_clone,
                    &chunk_range,
                )
                .await;

                let duration = Utc::now().signed_duration_since(chunk_start).num_seconds() as u64;

                match result {
                    Ok(hosts_found) => {
                        let message =
                            format!("Chunk {} completed: {} hosts found", index + 1, hosts_found);
                        progress_tx_clone.send(message).await.ok();

                        result_tx_clone
                            .send(ChunkScanResult {
                                chunk_range: chunk_range.clone(),
                                hosts_found,
                                scan_duration: duration,
                                success: true,
                                error: None,
                            })
                            .await
                            .ok();
                    }
                    Err(e) => {
                        let error_msg = format!("Chunk {} failed: {}", index + 1, e);
                        warn!("{}", error_msg);
                        progress_tx_clone.send(error_msg.clone()).await.ok();

                        result_tx_clone
                            .send(ChunkScanResult {
                                chunk_range: chunk_range.clone(),
                                hosts_found: 0,
                                scan_duration: duration,
                                success: false,
                                error: Some(e.to_string()),
                            })
                            .await
                            .ok();
                    }
                }
            });

            handles.push(handle);
        }

        // wait for all chunks to complete
        let mut total_hosts_found = 0;
        let mut successful_chunks = 0;
        let mut failed_chunks = 0;

        for _ in 0..chunks.len() {
            if let Some(result) = result_rx.recv().await {
                if result.success {
                    total_hosts_found += result.hosts_found;
                    successful_chunks += 1;
                } else {
                    failed_chunks += 1;
                }
            }
        }

        // wait for all tasks to complete
        for handle in handles {
            handle.await.ok();
        }

        // close progress channel and wait for reporter
        drop(progress_tx);
        progress_handle.await.ok();

        // update session with final results
        let mut updated_session = session;
        updated_session.end_time = Some(Utc::now());
        updated_session.total_hosts = total_hosts_found as i32;
        updated_session.hosts_up = total_hosts_found as i32; // assume all found hosts are up
        updated_session.hosts_down = 0;

        db.update_scan_session(&updated_session).await?;

        info!(
            "Parallel scan completed: {} chunks, {} successful, {} failed, {} total hosts found",
            chunks.len(),
            successful_chunks,
            failed_chunks,
            total_hosts_found
        );

        Ok(session_id)
    }

    fn create_chunk_config(&self, chunk: &NetworkRange) -> Result<ScanConfig> {
        let mut chunk_config = self.config.clone();
        chunk_config.target_range = chunk.to_cidr_string();
        chunk_config.max_concurrent_scans = 1; // one scan per chunk
        Ok(chunk_config)
    }

    async fn scan_chunk(
        chunk_config: &ScanConfig,
        db: &Database,
        session_id: Uuid,
        chunk_range: &str,
    ) -> Result<u32> {
        if chunk_config.use_zmap_discovery {
            // use hybrid zmap+nmap scanning
            let zmap_config = ZmapConfig::from_scan_config(chunk_config);
            let zmap_scanner = ZmapScanner::new(zmap_config);

            match zmap_scanner.scan_network().await {
                Ok(zmap_results) => {
                    if zmap_results.is_empty() {
                        debug!("No hosts found in chunk {}", chunk_range);
                        return Ok(0);
                    }

                    let nmap_scanner = NmapScanner::new(chunk_config.clone());
                    // for zmap results, we need to create a temporary session and then merge results
                    match nmap_scanner.scan_network_with_session(db, session_id).await {
                        Ok(hosts_found) => Ok(hosts_found),
                        Err(e) => {
                            warn!("Nmap scan failed for chunk {}: {}", chunk_range, e);
                            Ok(0)
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "Zmap scan failed for chunk {}, falling back to nmap: {}",
                        chunk_range, e
                    );
                    // fall back to traditional nmap scanning
                    let nmap_scanner = NmapScanner::new(chunk_config.clone());
                    match nmap_scanner.scan_network_with_session(db, session_id).await {
                        Ok(hosts_found) => Ok(hosts_found),
                        Err(e) => {
                            error!("Both zmap and nmap failed for chunk {}: {}", chunk_range, e);
                            Ok(0)
                        }
                    }
                }
            }
        } else {
            // use traditional nmap scanning with existing session
            let nmap_scanner = NmapScanner::new(chunk_config.clone());
            match nmap_scanner.scan_network_with_session(db, session_id).await {
                Ok(hosts_found) => Ok(hosts_found),
                Err(e) => {
                    warn!("Nmap scan failed for chunk {}: {}", chunk_range, e);
                    Ok(0)
                }
            }
        }
    }
}

// helper function to determine if a network range is large enough to require chunking
pub fn should_use_parallel_scanning(target_range: &str) -> bool {
    if let Ok(network_range) = NetworkRange::from_range(target_range) {
        let host_count = network_range.get_host_count();
        // use parallel scanning for networks larger than /22 (1024 hosts)
        host_count > 1024
    } else {
        false
    }
}

pub fn estimate_chunks_needed(target_range: &str, chunk_size: u8) -> Result<usize> {
    let network_range = NetworkRange::from_range(target_range)?;
    let chunks = network_range.split_into_chunks(chunk_size)?;
    Ok(chunks.len())
}
