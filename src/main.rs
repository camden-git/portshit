mod camera;
mod cli;
mod config;
mod database;
mod network;
mod nmap;
mod parallel_scanner;
mod pipeline_scanner;
mod zmap;

use anyhow::{Context, Result};
use clap::Parser;
use cli::{Cli, Commands, HostSummary, PortSummary};
use config::ScanConfig;
use database::Database;
use nmap::NmapScanner;
use parallel_scanner::{ParallelScanManager, should_use_parallel_scanning, estimate_chunks_needed};
use pipeline_scanner::{PipelineScanner, PipelineConfig};
use serde_json;
use std::fs;
use tracing::{error, info, warn};
use tracing_subscriber;
use uuid::Uuid;
use zmap::{ZmapConfig, ZmapScanner};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            target,
            target_list,
            ports,
            skip_non_pingable,
            intensity,
            os_detection,
            service_detection,
            script_scanning,
            version_light,
            scripts,
            turbo,
            two_pass,
            zmap_discovery,
            zmap_rate,
            zmap_interface,
            zmap_source_ip,
            database,
            max_concurrent,
            host_timeout,
            force_parallel,
            chunk_size,
            pipeline,
            discovery_threads,
            service_threads,
            camera_threads,
            resume_session,
            camera_auth,
            no_db,
        } => {
            let mut config = ScanConfig::from_env();
            
            // override config with cli arguments
            if let Some(t) = target {
                config.target_range = t;
            }
            if let Some(tl) = target_list {
                config.target_list_file = Some(tl);
            }
            if let Some(p) = ports {
                config.port_range = p;
            }
            if let Some(skip) = skip_non_pingable {
                config.skip_non_pingable = skip;
            }
            if let Some(i) = intensity {
                config.scan_intensity = i;
            }
            if let Some(os) = os_detection {
                config.os_detection = os;
            }
            if let Some(service) = service_detection {
                config.service_detection = service;
            }
            if let Some(script) = script_scanning {
                config.script_scanning = script;
            }
            if let Some(vl) = version_light {
                config.version_light = vl;
            }
            if let Some(scr) = scripts {
                config.scripts = Some(scr);
            }
            if let Some(t) = turbo {
                config.turbo_mode = t;
            }
            if let Some(tp) = two_pass {
                config.two_pass_scanning = tp;
            }
            if let Some(zmap) = zmap_discovery {
                config.use_zmap_discovery = zmap;
            }
            if let Some(rate) = zmap_rate {
                config.zmap_rate = rate;
            }
            if let Some(interface) = zmap_interface {
                config.zmap_interface = Some(interface);
            }
            if let Some(source_ip) = zmap_source_ip {
                config.zmap_source_ip = Some(source_ip);
            }
            if let Some(db) = database {
                config.database_path = db;
            }
            if let Some(max) = max_concurrent {
                config.max_concurrent_scans = max;
            }
            if let Some(timeout) = host_timeout {
                config.host_timeout = timeout;
            }
            if let Some(session_id) = resume_session {
                config.resume_session = Some(session_id);
            }
            if let Some(auth) = camera_auth {
                config.camera_auth = auth;
            }

            config.validate()?;
            
            let use_parallel = force_parallel.unwrap_or_else(|| should_use_parallel_scanning(&config.target_range));
            let use_pipeline = pipeline.unwrap_or(false);
            let chunk_size = chunk_size.unwrap_or(23); // default to /23

            info!("Starting scan with configuration: {:?}", config);

            let db = Database::new(&config.database_path).await?;
            
            if use_pipeline {
                info!("Using 3-stage pipeline scanning");
                
                let chunks_needed = estimate_chunks_needed(&config.target_range, chunk_size)?;
                info!("Network will be split into {} /{} chunks", chunks_needed, chunk_size);
                
                let mut pipeline_config = PipelineConfig::default();
                if let Some(discovery) = discovery_threads {
                    pipeline_config.discovery_threads = discovery;
                }
                if let Some(service) = service_threads {
                    pipeline_config.service_threads = service;
                }
                if let Some(camera) = camera_threads {
                    pipeline_config.camera_threads = camera;
                }
                
                let target_range = config.target_range.clone();
                let pipeline_scanner = PipelineScanner::new(config)
                    .with_pipeline_config(pipeline_config)
                    .with_chunk_size(chunk_size);
                let session_id = pipeline_scanner.scan_large_network(&db).await?;
                
                info!("Pipeline scan completed successfully!");
                println!("Scan session ID: {}", session_id);
                println!("Target range: {} (split into {} chunks)", target_range, chunks_needed);
                
                return Ok(());
            } else if use_parallel {
                info!("Using parallel chunked scanning");
                
                let chunks_needed = estimate_chunks_needed(&config.target_range, chunk_size)?;
                info!("Network will be split into {} /{} chunks", chunks_needed, chunk_size);
                
                let target_range = config.target_range.clone();
                let parallel_manager = ParallelScanManager::new(config.clone()).with_chunk_size(chunk_size);
                let session_id = parallel_manager.scan_large_network(&db).await?;
                
                info!("Parallel scan completed successfully!");
                println!("Scan session ID: {}", session_id);
                println!("Target range: {} (split into {} chunks)", target_range, chunks_needed);
                
                return Ok(());
            }
            
            if config.use_zmap_discovery {
                info!("Using zmap for initial host discovery");
                
                // create zmap configuration
                let zmap_config = ZmapConfig::from_scan_config(&config);
                zmap_config.validate()?;
                
                let zmap_scanner = ZmapScanner::new(zmap_config);
                
                let zmap_results = match zmap_scanner.scan_network().await {
                    Ok(results) => results,
                    Err(e) => {
                        warn!("Zmap scan failed: {}", e);

                        // fall back to traditional nmap scanning
                        let scanner = NmapScanner::new(config.clone());
                        match scanner.scan_network(&db).await {
                            Ok(session) => {
                                info!("Fallback nmap scan completed successfully");
                                println!("Scan session ID: {}", session.id);
                                println!("Target range: {}", session.target_range);
                                println!("Total hosts: {}", session.total_hosts);
                                println!("Hosts up: {}", session.hosts_up);
                                println!("Hosts down: {}", session.hosts_down);
                                if let Some(end_time) = session.end_time {
                                    let duration = end_time.signed_duration_since(session.start_time);
                                    println!("Duration: {} seconds", duration.num_seconds());
                                }
                                return Ok(());
                            }
                            Err(e) => {
                                error!("Fallback nmap scan also failed: {}", e);
                                return Err(e);
                            }
                        }
                    }
                };
                
                if zmap_results.is_empty() {
                    info!("No hosts discovered by zmap, skipping nmap scan");
                    return Ok(());
                }
                
                info!("Zmap discovered {} hosts, proceeding with nmap detailed scan", zmap_results.len());
                
                // Rrn nmap on discovered hosts
                let scanner = NmapScanner::new(config.clone());
                match scanner.scan_network_with_zmap_results(&db, zmap_results).await {
                    Ok(session) => {
                        info!("Hybrid zmap+nmap scan completed successfully!");
                        println!("Scan session ID: {}", session.id);
                        println!("Target range: {}", session.target_range);
                        println!("Total hosts: {}", session.total_hosts);
                        println!("Hosts up: {}", session.hosts_up);
                        println!("Hosts down: {}", session.hosts_down);
                        if let Some(end_time) = session.end_time {
                            let duration = end_time.signed_duration_since(session.start_time);
                            println!("Duration: {} seconds", duration.num_seconds());
                        }
                    }
                    Err(e) => {
                        error!("Hybrid scan failed: {}", e);
                        return Err(e);
                    }
                }
            } else {
                let scanner = NmapScanner::new(config.clone());
                match scanner.scan_network(&db).await {
                    Ok(session) => {
                        info!("Scan completed successfully");
                        println!("Scan session ID: {}", session.id);
                        println!("Target range: {}", session.target_range);
                        println!("Total hosts: {}", session.total_hosts);
                        println!("Hosts up: {}", session.hosts_up);
                        println!("Hosts down: {}", session.hosts_down);
                        if let Some(end_time) = session.end_time {
                            let duration = end_time.signed_duration_since(session.start_time);
                            println!("Duration: {} seconds", duration.num_seconds());
                        }
                    }
                    Err(e) => {
                        error!("Scan failed: {}", e);
                        return Err(e);
                    }
                }
            }
        }
        
        Commands::List { detailed, limit, database } => {
            let mut config = ScanConfig::from_env();
            if let Some(db_path) = database {
                config.database_path = db_path;
            }
            let db = Database::new(&config.database_path).await?;
            
            let mut sessions = db.get_scan_sessions().await?;
            
            if let Some(l) = limit {
                sessions.truncate(l);
            }
            
            if detailed {
                for session in sessions {
                    println!("Session ID: {}", session.id);
                    println!("Target range: {}", session.target_range);
                    println!("Start time: {}", session.start_time.format("%Y-%m-%d %H:%M:%S UTC"));
                    if let Some(end_time) = session.end_time {
                        println!("End time: {}", end_time.format("%Y-%m-%d %H:%M:%S UTC"));
                        let duration = end_time.signed_duration_since(session.start_time);
                        println!("Duration: {} seconds", duration.num_seconds());
                    }
                    println!("Total hosts: {}", session.total_hosts);
                    println!("Hosts up: {}", session.hosts_up);
                    println!("Hosts down: {}", session.hosts_down);
                    println!("---");
                }
            } else {
                println!("{:<36} {:<20} {:<19} {:<8} {:<8} {:<8}", 
                    "Session ID", "Target Range", "Start Time", "Total", "Up", "Down");
                println!("{}", "-".repeat(100));
                
                for session in sessions {
                    println!("{:<36} {:<20} {:<19} {:<8} {:<8} {:<8}",
                        session.id,
                        session.target_range,
                        session.start_time.format("%Y-%m-%d %H:%M:%S"),
                        session.total_hosts,
                        session.hosts_up,
                        session.hosts_down
                    );
                }
            }
        }
        
        Commands::Show { session_id, hosts_only, open_ports_only, database } => {
            let mut config = ScanConfig::from_env();
            if let Some(db_path) = database {
                config.database_path = db_path;
            }
            let db = Database::new(&config.database_path).await?;
            
            let session_uuid = Uuid::parse_str(&session_id)
                .context("Invalid session ID format")?;
            
            let hosts = db.get_hosts_by_session(&session_uuid).await?;
            
            if hosts_only {
                for host in hosts {
                    println!("IP: {}", host.ip_address);
                    if let Some(hostname) = host.hostname {
                        println!("Hostname: {}", hostname);
                    }
                    println!("Status: {}", host.status);
                    if let Some(mac) = host.mac_address {
                        println!("MAC: {}", mac);
                    }
                    if let Some(vendor) = host.vendor {
                        println!("Vendor: {}", vendor);
                    }
                    if let Some(os_family) = host.os_family {
                        println!("OS Family: {}", os_family);
                    }
                    println!("---");
                }
            } else {
                for host in hosts {
                    println!("Host: {} ({})", 
                        host.ip_address, 
                        host.hostname.as_deref().unwrap_or("unknown")
                    );
                    println!("Status: {}", host.status);
                    
                    let ports = db.get_ports_by_host(&host.id).await?;
                    let open_ports: Vec<_> = if open_ports_only {
                        ports.into_iter().filter(|p| p.state == "open").collect()
                    } else {
                        ports
                    };
                    
                    if !open_ports.is_empty() {
                        println!("Ports:");
                        for port in open_ports {
                            print!("  {}/{} {}", port.port_number, port.protocol, port.state);
                            if let Some(service) = port.service_name {
                                print!(" ({})", service);
                            }
                            if let Some(version) = port.service_version {
                                print!(" {}", version);
                            }
                            println!();
                        }
                    } else {
                        println!("No open ports found");
                    }
                    println!("---");
                }
            }
        }
        
        Commands::Export { session_id, format: _, output } => {
            let config = ScanConfig::from_env();
            let db = Database::new(&config.database_path).await?;
            
            let session_uuid = Uuid::parse_str(&session_id)
                .context("Invalid session ID format")?;
            
            let sessions = db.get_scan_sessions().await?;
            let _session = sessions.into_iter()
                .find(|s| s.id == session_uuid)
                .context("Session not found")?;
            
            let hosts = db.get_hosts_by_session(&session_uuid).await?;
            
            let mut export_data = Vec::new();
            
            for host in hosts {
                let ports = db.get_ports_by_host(&host.id).await?;
                
                let mut services = Vec::new();
                let mut port_summaries = Vec::new();
                
                for port in ports {
                    if let Some(service_name) = &port.service_name {
                        services.push(service_name.clone());
                    }
                    
                    port_summaries.push(PortSummary {
                        port_number: port.port_number,
                        protocol: port.protocol,
                        state: port.state,
                        service_name: port.service_name,
                        service_version: port.service_version,
                        service_product: port.service_product,
                    });
                }
                
                let os_info = if let (Some(family), Some(gen)) = (&host.os_family, &host.os_gen) {
                    Some(format!("{} {}", family, gen))
                } else {
                    host.os_family.clone()
                };
                
                export_data.push(HostSummary {
                    ip_address: host.ip_address,
                    hostname: host.hostname,
                    status: host.status,
                    open_ports: port_summaries.iter().filter(|p| p.state == "open").count() as i32,
                    services,
                    os_info,
                });
            }
            
            let output_data = serde_json::to_string_pretty(&export_data)?;
            
            if let Some(output_path) = output {
                fs::write(&output_path, &output_data)?;
                println!("Exported {} hosts to {}", export_data.len(), output_path);
            } else {
                println!("{}", output_data);
            }
        }
        
        Commands::Init { database } => {
            let db_path = database.unwrap_or_else(|| "scan_results.db".to_string());
            let _db = Database::new(&db_path).await?;
            println!("Database initialized at: {}", db_path);
        }
        
        Commands::Cameras { session_id, database } => {
            let mut config = ScanConfig::from_env();
            if let Some(db_path) = database {
                config.database_path = db_path;
            }
            let db = Database::new(&config.database_path).await?;
            
            let session_uuid = Uuid::parse_str(&session_id)
                .context("Invalid session ID format")?;
            
            let screenshots = db.get_camera_screenshots_by_session(&session_uuid).await?;
            
            if screenshots.is_empty() {
                println!("No camera screenshots found for session: {}", session_id);
            } else {
                println!("Camera screenshots for session: {}", session_id);
                println!("{:<15} {:<50} {:<30} {}", "Host IP", "RTSP URL", "Screenshot Path", "Captured At");
                println!("{}", "-".repeat(120));
                
                for screenshot in screenshots {
                    println!("{:<15} {:<50} {:<30} {}", 
                        screenshot.host_ip,
                        screenshot.rtsp_url,
                        screenshot.screenshot_path,
                        screenshot.captured_at.format("%Y-%m-%d %H:%M:%S")
                    );
                }
            }
        }
    }

    Ok(())
}
