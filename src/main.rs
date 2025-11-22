mod camera;
mod cli;
mod config;
mod database;
mod network;
mod nmap;
mod parallel_scanner;
mod pipeline_scanner;
mod subnet_detector;
mod webserver;
mod zmap;

use anyhow::{Context, Result};
use clap::Parser;
use cli::{Cli, Commands, DeviceCommands, HostSummary, PortSummary, SubnetCommands};
use config::ScanConfig;
use database::{Database, ScanSession, Host, Port, DeviceCatalog};
use nmap::NmapScanner;
use parallel_scanner::{estimate_chunks_needed, should_use_parallel_scanning, ParallelScanManager};
use pipeline_scanner::{PipelineConfig, PipelineScanner};
use std::fs;
use tracing::{info, warn};
use tracing_subscriber;
use uuid::Uuid;
use zmap::{ZmapConfig, ZmapScanner};

#[tokio::main]
async fn main() -> Result<()> {
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
            no_db: _,
        } => {
            handle_scan_command(ScanArgs {
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
            })
            .await
        }
        Commands::List {
            detailed,
            limit,
            database,
        } => handle_list_command(detailed, limit, database).await,
        Commands::Show {
            session_id,
            hosts_only,
            open_ports_only,
            database,
        } => handle_show_command(session_id, hosts_only, open_ports_only, database).await,
        Commands::Export {
            session_id,
            format: _,
            output,
        } => handle_export_command(session_id, output).await,
        Commands::Init { database } => handle_init_command(database).await,
        Commands::Cameras {
            session_id,
            database,
        } => handle_cameras_command(session_id, database).await,
        Commands::Device { device_command } => handle_device_command(device_command).await,
        Commands::Subnet { subnet_command } => handle_subnet_command(subnet_command).await,
        Commands::Server {
            database,
            api_key,
            bind,
        } => handle_server_command(database, api_key, bind).await,
    }
}

/// Arguments for the scan command
struct ScanArgs {
    target: Option<String>,
    target_list: Option<String>,
    ports: Option<String>,
    skip_non_pingable: Option<bool>,
    intensity: Option<u8>,
    os_detection: Option<bool>,
    service_detection: Option<bool>,
    script_scanning: Option<bool>,
    version_light: Option<bool>,
    scripts: Option<String>,
    turbo: Option<bool>,
    two_pass: Option<bool>,
    zmap_discovery: Option<bool>,
    zmap_rate: Option<u32>,
    zmap_interface: Option<String>,
    zmap_source_ip: Option<String>,
    database: Option<String>,
    max_concurrent: Option<usize>,
    host_timeout: Option<u64>,
    force_parallel: Option<bool>,
    chunk_size: Option<u8>,
    pipeline: Option<bool>,
    discovery_threads: Option<usize>,
    service_threads: Option<usize>,
    camera_threads: Option<usize>,
    resume_session: Option<String>,
    camera_auth: Option<String>,
}

/// Handles the scan command with all its options
async fn handle_scan_command(args: ScanArgs) -> Result<()> {
    let mut config = build_scan_config(&args)?;
    let db = create_database(&config.database_path).await?;

    let use_parallel = args
        .force_parallel
        .unwrap_or_else(|| should_use_parallel_scanning(&config.target_range));
    let use_pipeline = args.pipeline.unwrap_or(false);
    let chunk_size = args.chunk_size.unwrap_or(23);

    info!("Starting scan with configuration: {:?}", config);

    if use_pipeline {
        run_pipeline_scan(&config, &db, args, chunk_size).await
    } else if use_parallel {
        run_parallel_scan(&config, &db, chunk_size).await
    } else if config.use_zmap_discovery {
        run_zmap_scan(&config, &db).await
    } else {
        run_standard_scan(&config, &db).await
    }
}

/// Builds a ScanConfig from CLI arguments, overriding defaults from environment
fn build_scan_config(args: &ScanArgs) -> Result<ScanConfig> {
    let mut config = ScanConfig::from_env();

    // Apply CLI overrides
    if let Some(target) = &args.target {
        config.target_range = target.clone();
    }
    if let Some(target_list) = &args.target_list {
        config.target_list_file = Some(target_list.clone());
    }
    if let Some(ports) = &args.ports {
        config.port_range = ports.clone();
    }
    if let Some(skip) = args.skip_non_pingable {
        config.skip_non_pingable = skip;
    }
    if let Some(intensity) = args.intensity {
        config.scan_intensity = intensity;
    }
    if let Some(os) = args.os_detection {
        config.os_detection = os;
    }
    if let Some(service) = args.service_detection {
        config.service_detection = service;
    }
    if let Some(script) = args.script_scanning {
        config.script_scanning = script;
    }
    if let Some(version_light) = args.version_light {
        config.version_light = version_light;
    }
    if let Some(scripts) = &args.scripts {
        config.scripts = Some(scripts.clone());
    }
    if let Some(turbo) = args.turbo {
        config.turbo_mode = turbo;
    }
    if let Some(two_pass) = args.two_pass {
        config.two_pass_scanning = two_pass;
    }
    if let Some(zmap) = args.zmap_discovery {
        config.use_zmap_discovery = zmap;
    }
    if let Some(rate) = args.zmap_rate {
        config.zmap_rate = rate;
    }
    if let Some(interface) = &args.zmap_interface {
        config.zmap_interface = Some(interface.clone());
    }
    if let Some(source_ip) = &args.zmap_source_ip {
        config.zmap_source_ip = Some(source_ip.clone());
    }
    if let Some(db) = &args.database {
        config.database_path = db.clone();
    }
    if let Some(max) = args.max_concurrent {
        config.max_concurrent_scans = max;
    }
    if let Some(timeout) = args.host_timeout {
        config.host_timeout = timeout;
    }
    if let Some(session_id) = &args.resume_session {
        config.resume_session = Some(session_id.clone());
    }
    if let Some(auth) = &args.camera_auth {
        config.camera_auth = auth.clone();
    }

    config.validate()?;
    Ok(config)
}

/// Runs a pipeline scan
async fn run_pipeline_scan(
    config: &ScanConfig,
    db: &Database,
    args: ScanArgs,
    chunk_size: u8,
) -> Result<()> {
    info!("Using 3-stage pipeline scanning");

    let chunks_needed = estimate_chunks_needed(&config.target_range, chunk_size)?;
    info!(
        "Network will be split into {} /{} chunks",
        chunks_needed, chunk_size
    );

    let mut pipeline_config = PipelineConfig::default();
    if let Some(discovery) = args.discovery_threads {
        pipeline_config.discovery_threads = discovery;
    }
    if let Some(service) = args.service_threads {
        pipeline_config.service_threads = service;
    }
    if let Some(camera) = args.camera_threads {
        pipeline_config.camera_threads = camera;
    }

    let target_range = config.target_range.clone();
    let pipeline_scanner = PipelineScanner::new(config.clone())
        .with_pipeline_config(pipeline_config)
        .with_chunk_size(chunk_size);
    let session_id = pipeline_scanner.scan_large_network(db).await?;

    info!("Pipeline scan completed successfully!");
    print_scan_summary(&session_id, &target_range, Some(chunks_needed));

    // Auto-detect subnets after scan
    if let Err(e) = auto_detect_subnets_after_scan(db).await {
        warn!("Failed to auto-detect subnets after scan: {}", e);
    }

    Ok(())
}

/// Runs a parallel scan
async fn run_parallel_scan(config: &ScanConfig, db: &Database, chunk_size: u8) -> Result<()> {
    info!("Using parallel chunked scanning");

    let chunks_needed = estimate_chunks_needed(&config.target_range, chunk_size)?;
    info!(
        "Network will be split into {} /{} chunks",
        chunks_needed, chunk_size
    );

    let target_range = config.target_range.clone();
    let parallel_manager = ParallelScanManager::new(config.clone()).with_chunk_size(chunk_size);
    let session_id = parallel_manager.scan_large_network(db).await?;

    info!("Parallel scan completed successfully!");
    print_scan_summary(&session_id, &target_range, Some(chunks_needed));

    // Auto-detect subnets after scan
    if let Err(e) = auto_detect_subnets_after_scan(db).await {
        warn!("Failed to auto-detect subnets after scan: {}", e);
    }

    Ok(())
}

/// Runs a zmap-based scan with fallback to standard nmap
async fn run_zmap_scan(config: &ScanConfig, db: &Database) -> Result<()> {
    info!("Using zmap for initial host discovery");

    let zmap_config = ZmapConfig::from_scan_config(config);
    zmap_config.validate()?;

    let zmap_scanner = ZmapScanner::new(zmap_config);
    let zmap_results = match zmap_scanner.scan_network().await {
        Ok(results) => results,
        Err(e) => {
            warn!("Zmap scan failed: {}, falling back to nmap", e);
            return run_standard_scan(config, db).await;
        }
    };

    if zmap_results.is_empty() {
        info!("No hosts discovered by zmap, skipping nmap scan");
        return Ok(());
    }

    info!(
        "Zmap discovered {} hosts, proceeding with nmap detailed scan",
        zmap_results.len()
    );

    let scanner = NmapScanner::new(config.clone());
    let session = scanner
        .scan_network_with_zmap_results(db, zmap_results)
        .await
        .context("Hybrid zmap+nmap scan failed")?;

    info!("Hybrid zmap+nmap scan completed successfully!");
    print_session_details(&session);

    // Auto-detect subnets after scan
    if let Err(e) = auto_detect_subnets_after_scan(db).await {
        warn!("Failed to auto-detect subnets after scan: {}", e);
    }

    Ok(())
}

/// Runs a standard nmap scan
async fn run_standard_scan(config: &ScanConfig, db: &Database) -> Result<()> {
    let scanner = NmapScanner::new(config.clone());
    let session = scanner.scan_network(db).await.context("Scan failed")?;

    info!("Scan completed successfully");
    print_session_details(&session);

    // Auto-detect subnets after scan
    if let Err(e) = auto_detect_subnets_after_scan(db).await {
        warn!("Failed to auto-detect subnets after scan: {}", e);
    }

    Ok(())
}

/// Handles the list command
async fn handle_list_command(
    detailed: bool,
    limit: Option<usize>,
    database: Option<String>,
) -> Result<()> {
    let config = get_config_with_database(database);
    let db = create_database(&config.database_path).await?;

    let mut sessions = db.get_scan_sessions().await?;
    if let Some(l) = limit {
        sessions.truncate(l);
    }

    if detailed {
        print_sessions_detailed(&sessions);
    } else {
        print_sessions_table(&sessions);
    }

    Ok(())
}

/// Handles the show command
async fn handle_show_command(
    session_id: String,
    hosts_only: bool,
    open_ports_only: bool,
    database: Option<String>,
) -> Result<()> {
    let config = get_config_with_database(database);
    let db = create_database(&config.database_path).await?;

    let session_uuid = Uuid::parse_str(&session_id).context("Invalid session ID format")?;
    let hosts = db.get_hosts_by_session(&session_uuid).await?;

    if hosts_only {
        print_hosts_only(&hosts);
    } else {
        print_hosts_with_ports(&hosts, &db, open_ports_only).await?;
    }

    Ok(())
}

/// Handles the export command
async fn handle_export_command(session_id: String, output: Option<String>) -> Result<()> {
    let config = ScanConfig::from_env();
    let db = create_database(&config.database_path).await?;

    let session_uuid = Uuid::parse_str(&session_id).context("Invalid session ID format")?;

    // Verify session exists
    let sessions = db.get_scan_sessions().await?;
    sessions
        .into_iter()
        .find(|s| s.id == session_uuid)
        .context("Session not found")?;

    let hosts = db.get_hosts_by_session(&session_uuid).await?;
    let export_data = build_export_data(&hosts, &db).await?;
    let output_data = serde_json::to_string_pretty(&export_data)?;

    if let Some(output_path) = output {
        fs::write(&output_path, &output_data)?;
        println!("Exported {} hosts to {}", export_data.len(), output_path);
    } else {
        println!("{}", output_data);
    }

    Ok(())
}

/// Handles the init command
async fn handle_init_command(database: Option<String>) -> Result<()> {
    let db_path = database.unwrap_or_else(|| "scan_results.db".to_string());
    let _db = create_database(&db_path).await?;
    println!("Database initialized at: {}", db_path);
    Ok(())
}

/// Handles the cameras command
async fn handle_cameras_command(session_id: String, database: Option<String>) -> Result<()> {
    let config = get_config_with_database(database);
    let db = create_database(&config.database_path).await?;

    let session_uuid = Uuid::parse_str(&session_id).context("Invalid session ID format")?;
    let screenshots = db.get_camera_screenshots_by_session(&session_uuid).await?;

    if screenshots.is_empty() {
        println!("No camera screenshots found for session: {}", session_id);
    } else {
        print_camera_screenshots(&session_id, &screenshots);
    }

    Ok(())
}

/// Handles device catalog commands
async fn handle_device_command(command: DeviceCommands) -> Result<()> {
    match command {
        DeviceCommands::Set {
            ip_address,
            name,
            description,
            campus,
            latitude,
            longitude,
            floor,
            database,
        } => handle_device_set(ip_address, name, description, campus, latitude, longitude, floor, database).await,
        DeviceCommands::Show { ip_address, database } => {
            handle_device_show(ip_address, database).await
        }
        DeviceCommands::History { ip_address, database } => {
            handle_device_history(ip_address, database).await
        }
        DeviceCommands::List { database } => handle_device_list(database).await,
    }
}

/// Handles device set command
async fn handle_device_set(
    ip_address: String,
    name: Option<String>,
    description: Option<String>,
    campus: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    floor: Option<i32>,
    database: Option<String>,
) -> Result<()> {
    let config = get_config_with_database(database);
    let db = create_database(&config.database_path).await?;

    // Get existing catalog entry or create new one
    let existing = db.get_device_catalog(&ip_address).await?;
    let now = chrono::Utc::now();

    let mut catalog = existing.unwrap_or_else(|| DeviceCatalog {
        ip_address: ip_address.clone(),
        name: None,
        description: None,
        campus_name: None,
        latitude: None,
        longitude: None,
        floor_number: None,
        updated_at: now,
        created_at: now,
    });

    // Update fields if provided
    if let Some(n) = name {
        catalog.name = Some(n);
    }
    if let Some(d) = description {
        catalog.description = Some(d);
    }
    if let Some(c) = campus {
        catalog.campus_name = Some(c);
    }
    if let Some(lat) = latitude {
        catalog.latitude = Some(lat);
    }
    if let Some(lon) = longitude {
        catalog.longitude = Some(lon);
    }
    if let Some(f) = floor {
        catalog.floor_number = Some(f);
    }

    db.upsert_device_catalog(&catalog).await?;
    println!("Device catalog updated for IP: {}", ip_address);
    Ok(())
}

/// Handles device show command
async fn handle_device_show(ip_address: String, database: Option<String>) -> Result<()> {
    let config = get_config_with_database(database);
    let db = create_database(&config.database_path).await?;

    let catalog = db.get_device_catalog(&ip_address).await?;

    if let Some(catalog) = catalog {
        println!("Device Catalog for IP: {}", ip_address);
        println!("  Name: {}", catalog.name.as_deref().unwrap_or("N/A"));
        println!("  Description: {}", catalog.description.as_deref().unwrap_or("N/A"));
        println!("  Campus: {}", catalog.campus_name.as_deref().unwrap_or("N/A"));
        
        if let (Some(lat), Some(lon)) = (catalog.latitude, catalog.longitude) {
            println!("  Location: {}, {}", lat, lon);
        }
        
        if let Some(floor) = catalog.floor_number {
            println!("  Floor: {}", floor);
        }
        
        println!("  Created: {}", catalog.created_at.format("%Y-%m-%d %H:%M:%S UTC"));
        println!("  Updated: {}", catalog.updated_at.format("%Y-%m-%d %H:%M:%S UTC"));
    } else {
        println!("No catalog entry found for IP: {}", ip_address);
    }

    Ok(())
}

/// Handles device history command
async fn handle_device_history(ip_address: String, database: Option<String>) -> Result<()> {
    let config = get_config_with_database(database);
    let db = create_database(&config.database_path).await?;

    let history = db.get_host_history(&ip_address).await?;

    if history.is_empty() {
        println!("No history found for IP: {}", ip_address);
        return Ok(());
    }

    println!("History for IP: {}", ip_address);
    println!("{}", "=".repeat(80));

    for (idx, entry) in history.iter().enumerate() {
        if idx > 0 {
            println!();
        }
        
        println!("Snapshot {} - {}", idx + 1, entry.snapshot_at.format("%Y-%m-%d %H:%M:%S UTC"));
        println!("  Session ID: {}", entry.scan_session_id);
        println!("  Status: {}", entry.status);
        
        if let Some(hostname) = &entry.hostname {
            println!("  Hostname: {}", hostname);
        }
        
        if let Some(mac) = &entry.mac_address {
            println!("  MAC: {}", mac);
        }
        
        if let Some(vendor) = &entry.vendor {
            println!("  Vendor: {}", vendor);
        }
        
        if let Some(os_family) = &entry.os_family {
            println!("  OS Family: {}", os_family);
            if let Some(os_gen) = &entry.os_gen {
                println!("  OS Gen: {}", os_gen);
            }
        }
        
        // Parse and display ports snapshot
        if let Ok(ports) = serde_json::from_str::<Vec<Port>>(&entry.ports_snapshot) {
            let open_ports: Vec<_> = ports.iter().filter(|p| p.state == "open").collect();
            if !open_ports.is_empty() {
                println!("  Open Ports: {}", open_ports.len());
                for port in open_ports.iter().take(10) {
                    print!("    {}/{}", port.port_number, port.protocol);
                    if let Some(service) = &port.service_name {
                        print!(" ({})", service);
                    }
                    println!();
                }
                if open_ports.len() > 10 {
                    println!("    ... and {} more", open_ports.len() - 10);
                }
            }
        }
    }

    Ok(())
}

/// Handles device list command
async fn handle_device_list(database: Option<String>) -> Result<()> {
    let config = get_config_with_database(database);
    let db = create_database(&config.database_path).await?;

    let devices = db.get_all_device_catalog().await?;

    if devices.is_empty() {
        println!("No devices in catalog");
        return Ok(());
    }

    println!("{:<15} {:<20} {:<30} {:<15}", "IP Address", "Name", "Campus", "Location");
    println!("{}", "-".repeat(80));

    for device in devices {
        let name = device.name.as_deref().unwrap_or("N/A");
        let campus = device.campus_name.as_deref().unwrap_or("N/A");
        
        let location = if let (Some(lat), Some(lon)) = (device.latitude, device.longitude) {
            format!("{}, {}", lat, lon)
        } else {
            "N/A".to_string()
        };
        
        println!("{:<15} {:<20} {:<30} {:<15}", device.ip_address, name, campus, location);
    }

    Ok(())
}

/// Handles subnet catalog commands
async fn handle_subnet_command(command: SubnetCommands) -> Result<()> {
    match command {
        SubnetCommands::Detect { database } => handle_subnet_detect(database).await,
        SubnetCommands::List { status, database } => handle_subnet_list(status, database).await,
        SubnetCommands::Show { cidr, database } => handle_subnet_show(cidr, database).await,
        SubnetCommands::Set {
            cidr,
            name,
            campus,
            database,
        } => handle_subnet_set(cidr, name, campus, database).await,
        SubnetCommands::Change {
            old_cidr,
            new_cidr,
            database,
        } => handle_subnet_change(old_cidr, new_cidr, database).await,
        SubnetCommands::Delete { cidr, database } => handle_subnet_delete(cidr, database).await,
    }
}

/// Handles subnet detect command
async fn handle_subnet_detect(database: Option<String>) -> Result<()> {
    let config = get_config_with_database(database);
    let db = create_database(&config.database_path).await?;

    println!("Detecting subnets from discovered IP addresses...");

    let detected_subnets = subnet_detector::SubnetDetector::detect_subnets(&db).await?;

    if detected_subnets.is_empty() {
        println!("No subnets detected");
        return Ok(());
    }

    println!("Detected {} subnets", detected_subnets.len());

    // Update catalog
    subnet_detector::SubnetDetector::update_subnet_catalog(&db, &detected_subnets).await?;

    println!("Subnet catalog updated successfully");
    Ok(())
}

/// Handles subnet list command
async fn handle_subnet_list(status: Option<String>, database: Option<String>) -> Result<()> {
    let config = get_config_with_database(database);
    let db = create_database(&config.database_path).await?;

    let subnets = if let Some(status_filter) = status {
        db.get_subnets_by_status(&status_filter).await?
    } else {
        db.get_all_subnet_catalog().await?
    };

    if subnets.is_empty() {
        println!("No subnets found");
        return Ok(());
    }

    println!(
        "{:<20} {:<30} {:<15} {:<8} {:<8} {:<12} {:<10}",
        "CIDR", "Name", "Campus", "Size", "Active", "Utilization", "Status"
    );
    println!("{}", "-".repeat(120));

    for subnet in subnets {
        let name = subnet.name.as_deref().unwrap_or("N/A");
        let campus = subnet.campus_name.as_deref().unwrap_or("N/A");
        println!(
            "{:<20} {:<30} {:<15} {:<8} {:<8} {:<11.2}% {:<10}",
            subnet.cidr,
            name,
            campus,
            format!("/{}", subnet.subnet_size),
            subnet.active_ips,
            subnet.utilization_percent,
            subnet.status
        );
    }

    Ok(())
}

/// Handles subnet show command
async fn handle_subnet_show(cidr: String, database: Option<String>) -> Result<()> {
    let config = get_config_with_database(database);
    let db = create_database(&config.database_path).await?;

    let subnet = db.get_subnet_catalog(&cidr).await?;

    if let Some(subnet) = subnet {
        println!("Subnet: {}", subnet.cidr);
        println!("  Name: {}", subnet.name.as_deref().unwrap_or("N/A"));
        println!("  Campus: {}", subnet.campus_name.as_deref().unwrap_or("N/A"));
        println!("  Subnet Size: /{}", subnet.subnet_size);
        println!("  Total IPs: {}", subnet.total_ips);
        println!("  Active IPs: {}", subnet.active_ips);
        println!("  Utilization: {:.2}%", subnet.utilization_percent);
        println!("  Status: {}", subnet.status);
        println!(
            "  First Discovered: {}",
            subnet.first_discovered.format("%Y-%m-%d %H:%M:%S UTC")
        );
        println!(
            "  Last Seen: {}",
            subnet.last_seen.format("%Y-%m-%d %H:%M:%S UTC")
        );
        println!("  Discovery Sessions: {}", subnet.discovery_sessions);
    } else {
        println!("Subnet not found: {}", cidr);
    }

    Ok(())
}

/// Handles subnet set command
async fn handle_subnet_set(
    cidr: String,
    name: Option<String>,
    campus: Option<String>,
    database: Option<String>,
) -> Result<()> {
    let config = get_config_with_database(database);
    let db = create_database(&config.database_path).await?;

    db.update_subnet_metadata(&cidr, name, campus)
        .await
        .context(format!("Failed to update subnet metadata for {}", cidr))?;

    println!("Subnet metadata updated for: {}", cidr);
    Ok(())
}

/// Handles subnet change command
async fn handle_subnet_change(
    old_cidr: String,
    new_cidr: String,
    database: Option<String>,
) -> Result<()> {
    let config = get_config_with_database(database);
    let db = create_database(&config.database_path).await?;

    db.change_subnet_cidr(&old_cidr, &new_cidr)
        .await
        .context(format!(
            "Failed to change subnet CIDR from {} to {}",
            old_cidr, new_cidr
        ))?;

    println!("Subnet CIDR changed from {} to {}", old_cidr, new_cidr);
    Ok(())
}

/// Handles subnet delete command
async fn handle_subnet_delete(cidr: String, database: Option<String>) -> Result<()> {
    let config = get_config_with_database(database);
    let db = create_database(&config.database_path).await?;

    db.delete_subnet_catalog(&cidr)
        .await
        .context(format!("Failed to delete subnet {}", cidr))?;

    println!("Subnet deleted: {}", cidr);
    Ok(())
}

/// Handles server command
async fn handle_server_command(
    database: Option<String>,
    api_key: Option<String>,
    bind: String,
) -> Result<()> {
    let config = get_config_with_database(database);
    
    // Get API key from argument, environment variable, or generate one
    let api_key = api_key
        .or_else(|| std::env::var("API_KEY").ok())
        .unwrap_or_else(|| {
            // Generate a random API key if none provided
            use uuid::Uuid;
            let key = Uuid::new_v4().to_string();
            warn!("No API key provided. Generated API key: {}", key);
            warn!("Set API_KEY environment variable or use --api-key flag for production");
            key
        });

    webserver::run_server(config.database_path, api_key, bind).await
}

/// Automatically detects subnets after a scan completes
async fn auto_detect_subnets_after_scan(db: &Database) -> Result<()> {
    info!("Auto-detecting subnets from scan results...");
    
    let detected_subnets = subnet_detector::SubnetDetector::detect_subnets(db).await?;
    
    if !detected_subnets.is_empty() {
        subnet_detector::SubnetDetector::update_subnet_catalog(db, &detected_subnets).await?;
        info!("Auto-detected {} subnets", detected_subnets.len());
    }
    
    Ok(())
}

/// Creates a database connection
async fn create_database(database_path: &str) -> Result<Database> {
    Database::new(database_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create database: {}", e))
}

/// Gets config with optional database override
fn get_config_with_database(database: Option<String>) -> ScanConfig {
    let mut config = ScanConfig::from_env();
    if let Some(db_path) = database {
        config.database_path = db_path;
    }
    config
}

/// Prints scan session summary
fn print_scan_summary(session_id: &Uuid, target_range: &str, chunks: Option<usize>) {
    println!("Scan session ID: {}", session_id);
    if let Some(chunks) = chunks {
        println!(
            "Target range: {} (split into {} chunks)",
            target_range, chunks
        );
    } else {
        println!("Target range: {}", target_range);
    }
}

/// Prints detailed session information
fn print_session_details(session: &ScanSession) {
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

/// Prints sessions in detailed format
fn print_sessions_detailed(sessions: &[ScanSession]) {
    for session in sessions {
        println!("Session ID: {}", session.id);
        println!("Target range: {}", session.target_range);
        println!(
            "Start time: {}",
            session.start_time.format("%Y-%m-%d %H:%M:%S UTC")
        );
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
}

/// Prints sessions in table format
fn print_sessions_table(sessions: &[ScanSession]) {
    println!(
        "{:<36} {:<20} {:<19} {:<8} {:<8} {:<8}",
        "Session ID", "Target Range", "Start Time", "Total", "Up", "Down"
    );
    println!("{}", "-".repeat(100));

    for session in sessions {
        println!(
            "{:<36} {:<20} {:<19} {:<8} {:<8} {:<8}",
            session.id,
            session.target_range,
            session.start_time.format("%Y-%m-%d %H:%M:%S"),
            session.total_hosts,
            session.hosts_up,
            session.hosts_down
        );
    }
}

/// Prints hosts only (without ports)
fn print_hosts_only(hosts: &[Host]) {
    for host in hosts {
        println!("IP: {}", host.ip_address);
        if let Some(hostname) = &host.hostname {
            println!("Hostname: {}", hostname);
        }
        println!("Status: {}", host.status);
        if let Some(mac) = &host.mac_address {
            println!("MAC: {}", mac);
        }
        if let Some(vendor) = &host.vendor {
            println!("Vendor: {}", vendor);
        }
        if let Some(os_family) = &host.os_family {
            println!("OS Family: {}", os_family);
        }
        println!("---");
    }
}

/// Prints hosts with their ports
async fn print_hosts_with_ports(
    hosts: &[Host],
    db: &Database,
    open_ports_only: bool,
) -> Result<()> {
    for host in hosts {
        // Check for device catalog metadata
        let catalog = db.get_device_catalog(&host.ip_address).await?;
        
        if let Some(catalog) = &catalog {
            if let Some(name) = &catalog.name {
                println!("Host: {} ({})", host.ip_address, name);
            } else {
                println!(
                    "Host: {} ({})",
                    host.ip_address,
                    host.hostname.as_deref().unwrap_or("unknown")
                );
            }
        } else {
            println!(
                "Host: {} ({})",
                host.ip_address,
                host.hostname.as_deref().unwrap_or("unknown")
            );
        }
        
        if let Some(catalog) = &catalog {
            if let Some(description) = &catalog.description {
                println!("Description: {}", description);
            }
            if let Some(campus) = &catalog.campus_name {
                println!("Campus: {}", campus);
            }
            if let (Some(lat), Some(lon)) = (catalog.latitude, catalog.longitude) {
                print!("Location: {}, {}", lat, lon);
                if let Some(floor) = catalog.floor_number {
                    print!(" (Floor {})", floor);
                }
                println!();
            }
        }
        
        println!("Status: {}", host.status);

        let ports = db.get_ports_by_host(&host.id).await?;
        let filtered_ports: Vec<_> = if open_ports_only {
            ports.into_iter().filter(|p| p.state == "open").collect()
        } else {
            ports
        };

        if !filtered_ports.is_empty() {
            println!("Ports:");
            for port in filtered_ports {
                print!("  {}/{} {}", port.port_number, port.protocol, port.state);
                if let Some(service) = &port.service_name {
                    print!(" ({})", service);
                }
                if let Some(version) = &port.service_version {
                    print!(" {}", version);
                }
                println!();
            }
        } else {
            println!("No open ports found");
        }
        println!("---");
    }

    Ok(())
}

/// Builds export data from hosts
async fn build_export_data(hosts: &[Host], db: &Database) -> Result<Vec<HostSummary>> {
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
            ip_address: host.ip_address.clone(),
            hostname: host.hostname.clone(),
            status: host.status.clone(),
            open_ports: port_summaries.iter().filter(|p| p.state == "open").count() as i32,
            services,
            os_info,
        });
    }

    Ok(export_data)
}

/// Prints camera screenshots
fn print_camera_screenshots(session_id: &str, screenshots: &[database::CameraScreenshot]) {
    println!("Camera screenshots for session: {}", session_id);
    println!(
        "{:<15} {:<50} {:<30} {}",
        "Host IP", "RTSP URL", "Screenshot Path", "Captured At"
    );
    println!("{}", "-".repeat(120));

    for screenshot in screenshots {
        println!(
            "{:<15} {:<50} {:<30} {}",
            screenshot.host_ip,
            screenshot.rtsp_url,
            screenshot.screenshot_path,
            screenshot.captured_at.format("%Y-%m-%d %H:%M:%S")
        );
    }
}
