use crate::config::ScanConfig;
use crate::database::{Database, Host, Port, ScanSession, ScriptResult};
use anyhow::{Context, Result};
use chrono::Utc;
use quick_xml::de::from_str;
use roxmltree::Document;
use serde::{Deserialize, Serialize};
use std::process::Stdio;
use tokio::io::AsyncBufReadExt;
use tokio::process::Command;
use tokio::sync::Semaphore;
use tracing::{debug, error, info};
use uuid::Uuid;

#[derive(Debug, Deserialize, Serialize)]
pub struct NmapRun {
    #[serde(rename = "host")]
    pub hosts: Vec<NmapHost>,
    #[serde(rename = "runstats")]
    pub run_stats: NmapRunStats,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NmapRunStats {
    #[serde(rename = "finished")]
    pub finished: NmapFinished,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NmapFinished {
    #[serde(rename = "timestr")]
    pub time_str: String,
    #[serde(rename = "summary")]
    pub summary: String,
    #[serde(rename = "elapsed")]
    pub elapsed: f64,
    #[serde(rename = "exit")]
    pub exit: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NmapHost {
    #[serde(rename = "status")]
    pub status: Option<NmapHostStatus>,
    #[serde(rename = "address")]
    pub addresses: Option<Vec<NmapAddress>>,
    #[serde(rename = "hostnames")]
    pub hostnames: Option<NmapHostnames>,
    #[serde(rename = "ports")]
    pub ports: Option<NmapPorts>,
    #[serde(rename = "os")]
    pub os: Option<NmapOS>,
    #[serde(rename = "uptime")]
    pub uptime: Option<NmapUptime>,
    #[serde(rename = "script")]
    pub scripts: Option<Vec<NmapScript>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NmapHostStatus {
    #[serde(rename = "state")]
    pub state: String,
    #[serde(rename = "reason")]
    pub reason: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NmapAddress {
    #[serde(rename = "addr")]
    pub addr: String,
    #[serde(rename = "addrtype")]
    pub addr_type: String,
    #[serde(rename = "vendor")]
    pub vendor: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NmapHostnames {
    #[serde(rename = "hostname")]
    pub hostnames: Vec<NmapHostname>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NmapHostname {
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "type")]
    pub hostname_type: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NmapPorts {
    #[serde(rename = "port")]
    pub ports: Vec<NmapPort>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NmapPort {
    #[serde(rename = "protocol")]
    pub protocol: String,
    #[serde(rename = "portid")]
    pub port_id: String,
    #[serde(rename = "state")]
    pub state: Option<NmapPortState>,
    #[serde(rename = "service")]
    pub service: Option<NmapService>,
    #[serde(rename = "script")]
    pub scripts: Option<Vec<NmapScript>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NmapPortState {
    #[serde(rename = "state")]
    pub state: String,
    #[serde(rename = "reason")]
    pub reason: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NmapService {
    #[serde(rename = "name")]
    pub name: Option<String>,
    #[serde(rename = "product")]
    pub product: Option<String>,
    #[serde(rename = "version")]
    pub version: Option<String>,
    #[serde(rename = "extrainfo")]
    pub extra_info: Option<String>,
    #[serde(rename = "fingerprint")]
    pub fingerprint: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NmapOS {
    #[serde(rename = "osmatch")]
    pub os_matches: Option<Vec<NmapOSMatch>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NmapOSMatch {
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "accuracy")]
    pub accuracy: String,
    #[serde(rename = "osclass")]
    pub os_classes: Option<Vec<NmapOSClass>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NmapOSClass {
    #[serde(rename = "type")]
    pub os_type: String,
    #[serde(rename = "vendor")]
    pub vendor: String,
    #[serde(rename = "osfamily")]
    pub os_family: String,
    #[serde(rename = "osgen")]
    pub os_gen: String,
    #[serde(rename = "accuracy")]
    pub accuracy: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NmapUptime {
    #[serde(rename = "seconds")]
    pub seconds: i64,
    #[serde(rename = "lastboot")]
    pub last_boot: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NmapScript {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "output")]
    pub output: String,
}

pub struct NmapScanner {
    config: ScanConfig,
    semaphore: Semaphore,
}

impl NmapScanner {
    pub fn new(config: ScanConfig) -> Self {
        let max_concurrent = config.max_concurrent_scans;
        Self {
            config,
            semaphore: Semaphore::new(max_concurrent),
        }
    }

    pub async fn scan_network(&self, db: &Database) -> Result<ScanSession> {
        if self.config.two_pass_scanning {
            self.scan_network_two_pass(db).await
        } else {
            self.scan_network_single_pass(db).await
        }
    }

    pub async fn scan_network_with_zmap_results(&self, db: &Database, zmap_results: Vec<crate::zmap::ZmapResult>) -> Result<ScanSession> {
        if self.config.two_pass_scanning {
            self.scan_network_two_pass_with_zmap(db, zmap_results).await
        } else {
            self.scan_network_single_pass_with_zmap(db, zmap_results).await
        }
    }

    pub async fn scan_network_with_session(&self, db: &Database, session_id: Uuid) -> Result<u32> {
        if self.config.two_pass_scanning {
            self.scan_network_two_pass_with_session(db, session_id).await
        } else {
            self.scan_network_single_pass_with_session(db, session_id).await
        }
    }

    async fn scan_network_single_pass(&self, db: &Database) -> Result<ScanSession> {
        let session_id = Uuid::new_v4();
        let start_time = Utc::now();
        
        let session = ScanSession {
            id: session_id,
            target_range: self.get_target_description(),
            start_time,
            end_time: None,
            total_hosts: 0,
            hosts_up: 0,
            hosts_down: 0,
            config_json: serde_json::to_string(&self.config)?,
        };

        info!("Starting single-pass network scan for: {}", self.get_target_description());
        db.create_scan_session(&session).await?;

        let nmap_output = self.run_nmap_scan_full().await?;
        let nmap_result: NmapRun = match self.parse_nmap_xml_manually(&nmap_output) {
            Ok(result) => result,
            Err(e) => {
                error!("Manual XML parsing failed: {}", e);
                info!("Attempting serde XML parsing as fallback");
                from_str(&nmap_output)
                    .context("Both manual and serde XML parsing failed")?
            }
        };

        let (total_hosts, hosts_up, hosts_down) = self.process_nmap_results(&nmap_result, session_id, db).await?;

        let mut updated_session = session;
        updated_session.end_time = Some(Utc::now());
        updated_session.total_hosts = total_hosts;
        updated_session.hosts_up = hosts_up;
        updated_session.hosts_down = hosts_down;

        db.update_scan_session(&updated_session).await?;

        info!(
            "Single-pass scan completed: {} hosts total, {} up, {} down",
            total_hosts, hosts_up, hosts_down
        );

        Ok(updated_session)
    }

    async fn scan_network_two_pass(&self, db: &Database) -> Result<ScanSession> {
        let session_id = Uuid::new_v4();
        let start_time = Utc::now();
        
        let session = ScanSession {
            id: session_id,
            target_range: self.get_target_description(),
            start_time,
            end_time: None,
            total_hosts: 0,
            hosts_up: 0,
            hosts_down: 0,
            config_json: serde_json::to_string(&self.config)?,
        };

        info!("Starting two-pass network scan for: {}", self.get_target_description());
        db.create_scan_session(&session).await?;

        info!("Pass 1: Host discovery and port scanning");
        let nmap_output_pass1 = self.run_nmap_scan_discovery().await?;
        debug!("Nmap pass 1 XML output: {}", nmap_output_pass1);
        
        let nmap_result_pass1: NmapRun = match self.parse_nmap_xml_manually(&nmap_output_pass1) {
            Ok(result) => result,
            Err(e) => {
                error!("Manual XML parsing failed: {}", e);
                info!("Attempting serde XML parsing as fallback");
                from_str(&nmap_output_pass1)
                    .context("Both manual and serde XML parsing failed")?
            }
        };

        let (total_hosts, hosts_up, hosts_down) = self.process_nmap_results(&nmap_result_pass1, session_id, db).await?;

        if self.config.service_detection || self.config.script_scanning {
            info!("Pass 2: Service detection and script scanning on hosts with open ports");
            let hosts_with_open_ports = self.get_hosts_with_open_ports(db, session_id).await?;
            
            if !hosts_with_open_ports.is_empty() {
                let nmap_output_pass2 = self.run_nmap_scan_services(&hosts_with_open_ports).await?;
                let nmap_result_pass2: NmapRun = match from_str(&nmap_output_pass2) {
                    Ok(result) => result,
                    Err(e) => {
                        error!("Failed to parse nmap XML from pass 2 with serde: {}", e);
                        info!("Attempting manual XML parsing for pass 2 as fallback");
                        self.parse_nmap_xml_manually(&nmap_output_pass2)?
                    }
                };

                self.update_services_and_scripts(&nmap_result_pass2, db).await?;
            }
        }

        let mut updated_session = session;
        updated_session.end_time = Some(Utc::now());
        updated_session.total_hosts = total_hosts;
        updated_session.hosts_up = hosts_up;
        updated_session.hosts_down = hosts_down;

        db.update_scan_session(&updated_session).await?;

        info!(
            "Two-pass scan completed: {} hosts total, {} up, {} down",
            total_hosts, hosts_up, hosts_down
        );

        Ok(updated_session)
    }

    async fn scan_network_single_pass_with_zmap(&self, db: &Database, zmap_results: Vec<crate::zmap::ZmapResult>) -> Result<ScanSession> {
        let session_id = Uuid::new_v4();
        let start_time = Utc::now();
        
        let session = ScanSession {
            id: session_id,
            target_range: format!("zmap discovered hosts ({} hosts)", zmap_results.len()),
            start_time,
            end_time: None,
            total_hosts: 0,
            hosts_up: 0,
            hosts_down: 0,
            config_json: serde_json::to_string(&self.config)?,
        };

        info!("Starting single-pass nmap scan on {} zmap-discovered hosts", zmap_results.len());
        db.create_scan_session(&session).await?;

        // create a temporary file with the discovered hosts
        let temp_file = format!("/tmp/zmap_hosts_{}.txt", session_id);
        let mut hosts_content = String::new();
        for result in &zmap_results {
            if result.success {
                hosts_content.push_str(&format!("{}\n", result.ip_address));
            }
        }
        tokio::fs::write(&temp_file, hosts_content).await?;

        let nmap_output = self.run_nmap_scan_on_hosts_file(&temp_file).await?;
        let nmap_result: NmapRun = match self.parse_nmap_xml_manually(&nmap_output) {
            Ok(result) => result,
            Err(e) => {
                error!("Manual XML parsing failed: {}", e);
                info!("Attempting serde XML parsing as fallback");
                from_str(&nmap_output)
                    .context("Both manual and serde XML parsing failed")?
            }
        };

        let (total_hosts, hosts_up, hosts_down) = self.process_nmap_results(&nmap_result, session_id, db).await?;

        // clean up temp file
        let _ = tokio::fs::remove_file(&temp_file).await;

        let mut updated_session = session;
        updated_session.end_time = Some(Utc::now());
        updated_session.total_hosts = total_hosts;
        updated_session.hosts_up = hosts_up;
        updated_session.hosts_down = hosts_down;

        db.update_scan_session(&updated_session).await?;

        info!(
            "Single-pass nmap scan on zmap results completed: {} hosts total, {} up, {} down",
            total_hosts, hosts_up, hosts_down
        );

        Ok(updated_session)
    }

    async fn scan_network_two_pass_with_zmap(&self, db: &Database, zmap_results: Vec<crate::zmap::ZmapResult>) -> Result<ScanSession> {
        let session_id = Uuid::new_v4();
        let start_time = Utc::now();
        
        let session = ScanSession {
            id: session_id,
            target_range: format!("zmap discovered hosts ({} hosts)", zmap_results.len()),
            start_time,
            end_time: None,
            total_hosts: 0,
            hosts_up: 0,
            hosts_down: 0,
            config_json: serde_json::to_string(&self.config)?,
        };

        info!("Starting two-pass nmap scan on {} zmap-discovered hosts", zmap_results.len());
        db.create_scan_session(&session).await?;

        // create a temporary file with the discovered hosts
        let temp_file = format!("/tmp/zmap_hosts_{}.txt", session_id);
        let mut hosts_content = String::new();
        for result in &zmap_results {
            if result.success {
                hosts_content.push_str(&format!("{}\n", result.ip_address));
            }
        }
        tokio::fs::write(&temp_file, hosts_content).await?;

        info!("Pass 1: Port scanning on zmap-discovered hosts");
        let nmap_output_pass1 = self.run_nmap_scan_on_hosts_file_discovery(&temp_file).await?;
        let nmap_result_pass1: NmapRun = match self.parse_nmap_xml_manually(&nmap_output_pass1) {
            Ok(result) => result,
            Err(e) => {
                error!("Manual XML parsing for pass 1 failed: {}", e);
                info!("Attempting serde XML parsing for pass 1 as fallback");
                from_str(&nmap_output_pass1)
                    .context("Both manual and serde XML parsing failed for pass 1")?
            }
        };

        let (total_hosts, hosts_up, hosts_down) = self.process_nmap_results(&nmap_result_pass1, session_id, db).await?;

        if self.config.service_detection || self.config.script_scanning {
            info!("Pass 2: Service detection and script scanning on hosts with open ports");
            let hosts_with_open_ports = self.get_hosts_with_open_ports(db, session_id).await?;
            
            if !hosts_with_open_ports.is_empty() {
                let nmap_output_pass2 = self.run_nmap_scan_services(&hosts_with_open_ports).await?;
                let nmap_result_pass2: NmapRun = match from_str(&nmap_output_pass2) {
                    Ok(result) => result,
                    Err(e) => {
                        error!("Failed to parse nmap XML from pass 2 with serde: {}", e);
                        info!("Attempting manual XML parsing for pass 2 as fallback");
                        self.parse_nmap_xml_manually(&nmap_output_pass2)?
                    }
                };

                self.update_services_and_scripts(&nmap_result_pass2, db).await?;
            }
        }

        // clean up temp file
        let _ = tokio::fs::remove_file(&temp_file).await;

        let mut updated_session = session;
        updated_session.end_time = Some(Utc::now());
        updated_session.total_hosts = total_hosts;
        updated_session.hosts_up = hosts_up;
        updated_session.hosts_down = hosts_down;

        db.update_scan_session(&updated_session).await?;

        info!(
            "Two-pass nmap scan on zmap results completed: {} hosts total, {} up, {} down",
            total_hosts, hosts_up, hosts_down
        );

        Ok(updated_session)
    }

    async fn run_nmap_scan_on_hosts_file(&self, hosts_file: &str) -> Result<String> {
        self.run_nmap_scan_on_hosts_file_with_options(hosts_file, true, true, true).await
    }

    async fn run_nmap_scan_on_hosts_file_discovery(&self, hosts_file: &str) -> Result<String> {
        self.run_nmap_scan_on_hosts_file_with_options(hosts_file, false, false, false).await
    }

    async fn run_nmap_scan_on_hosts_file_with_options(&self, hosts_file: &str, service_detection: bool, os_detection: bool, script_scanning: bool) -> Result<String> {
        let _permit = self.semaphore.acquire().await?;
        
        let mut cmd = Command::new("nmap");
        
        // basic scan options
        cmd.arg("-oX").arg("-"); // output XML to stdout
        cmd.arg("-T").arg(self.config.scan_intensity.to_string()); // timing template
        
        // port scanning options
        if !self.config.port_range.is_empty() {
            cmd.arg("-p").arg(&self.config.port_range);
        }
        
        // skip host discovery since we already know hosts are up
        cmd.arg("-Pn");
        
        // turbo mode optimizations
        if self.config.turbo_mode {
            cmd.arg("--min-rate").arg("50000");
            cmd.arg("--max-retries").arg("1");
            cmd.arg("--max-rtt-timeout").arg("50ms");
            cmd.arg("--initial-rtt-timeout").arg("100ms");
            cmd.arg("--min-rtt-timeout").arg("800ms");
            cmd.arg("--max-hostgroup").arg("1000");
            cmd.arg("--max-parallelism").arg("1000");
        }
        
        // service detection
        if service_detection {
            cmd.arg("-sV"); // version detection
            if self.config.version_light {
                cmd.arg("--version-light"); // faster but less detailed version detection
            }
            if self.config.turbo_mode {
                cmd.arg("--version-intensity").arg("0"); // fastest version detection
            }
        }
        
        // OS detection
        if os_detection {
            cmd.arg("-O"); // OS detection
        }
        
        // script scanning
        if script_scanning {
            if let Some(ref scripts) = self.config.scripts {
                if !scripts.is_empty() {
                    cmd.arg("--script").arg(scripts); // custom scripts
                } else {
                    cmd.arg("-sC"); // default script scan if empty string
                }
            } else {
                cmd.arg("-sC"); // default script scan if not specified
            }
        }
        
        cmd.arg("--host-timeout").arg(format!("{}s", self.config.host_timeout));
        
        // target file
        cmd.arg("-iL").arg(hosts_file);
        
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        
        debug!("Running nmap command on hosts file: {:?}", cmd);
        
        let mut child = cmd.spawn()?;
        
        let stdout = child.stdout.take()
            .context("Failed to capture stdout")?;
        
        let mut output = String::new();
        let mut reader = tokio::io::BufReader::new(stdout);
        let mut line = String::new();
        
        while reader.read_line(&mut line).await? > 0 {
            output.push_str(&line);
            line.clear();
        }
        
        let status = child.wait().await?;
        
        if !status.success() {
            let stderr = child.stderr.take();
            if let Some(mut stderr) = stderr {
                let mut error_output = String::new();
                let mut stderr_reader = tokio::io::BufReader::new(&mut stderr);
                let mut error_line = String::new();
                
                while stderr_reader.read_line(&mut error_line).await? > 0 {
                    error_output.push_str(&error_line);
                    error_line.clear();
                }
                
                error!("Nmap stderr: {}", error_output);
            }
            
            return Err(anyhow::anyhow!("Nmap scan failed with exit code: {:?}", status.code()));
        }
        
        Ok(output)
    }

    async fn scan_network_single_pass_with_session(&self, db: &Database, session_id: Uuid) -> Result<u32> {
        let nmap_output = self.run_nmap_scan_full().await?;
        let nmap_result: NmapRun = match self.parse_nmap_xml_manually(&nmap_output) {
            Ok(result) => result,
            Err(e) => {
                error!("Manual XML parsing failed: {}", e);
                info!("Attempting serde XML parsing as fallback");
                from_str(&nmap_output)
                    .context("Both manual and serde XML parsing failed")?
            }
        };

        let (total_hosts, hosts_up, hosts_down) = self.process_nmap_results(&nmap_result, session_id, db).await?;
        Ok(hosts_up as u32)
    }

    async fn scan_network_two_pass_with_session(&self, db: &Database, session_id: Uuid) -> Result<u32> {
        info!("Pass 1: Host discovery and port scanning");
        let nmap_output_pass1 = self.run_nmap_scan_discovery().await?;
        debug!("Nmap pass 1 XML output: {}", nmap_output_pass1);
        
        let nmap_result_pass1: NmapRun = match self.parse_nmap_xml_manually(&nmap_output_pass1) {
            Ok(result) => result,
            Err(e) => {
                error!("Manual XML parsing failed: {}", e);
                info!("Attempting serde XML parsing as fallback");
                from_str(&nmap_output_pass1)
                    .context("Both manual and serde XML parsing failed")?
            }
        };

        let (total_hosts, hosts_up, hosts_down) = self.process_nmap_results(&nmap_result_pass1, session_id, db).await?;

        if self.config.service_detection || self.config.script_scanning {
            info!("Pass 2: Service detection and script scanning on hosts with open ports");
            let hosts_with_open_ports = self.get_hosts_with_open_ports(db, session_id).await?;
            
            if !hosts_with_open_ports.is_empty() {
                let nmap_output_pass2 = self.run_nmap_scan_services(&hosts_with_open_ports).await?;
                let nmap_result_pass2: NmapRun = match self.parse_nmap_xml_manually(&nmap_output_pass2) {
                    Ok(result) => result,
                    Err(e) => {
                        error!("Manual XML parsing for pass 2 failed: {}", e);
                        info!("Attempting serde XML parsing for pass 2 as fallback");
                        from_str(&nmap_output_pass2)
                            .context("Both manual and serde XML parsing failed for pass 2")?
                    }
                };

                self.update_services_and_scripts(&nmap_result_pass2, db).await?;
            }
        }

        info!(
            "Two-pass scan completed: {} hosts total, {} up, {} down",
            total_hosts, hosts_up, hosts_down
        );

        Ok(hosts_up as u32)
    }

    fn get_target_description(&self) -> String {
        if let Some(ref target_list) = self.config.target_list_file {
            format!("target list: {}", target_list)
        } else {
            self.config.target_range.clone()
        }
    }

    async fn run_nmap_scan_full(&self) -> Result<String> {
        self.run_nmap_scan_with_options(true, true, true).await
    }

    async fn run_nmap_scan_discovery(&self) -> Result<String> {
        self.run_nmap_scan_with_options(false, false, false).await
    }

    async fn run_nmap_scan_services(&self, hosts: &[String]) -> Result<String> {
        self.run_nmap_scan_services_on_hosts(hosts).await
    }

    async fn run_nmap_scan_with_options(&self, service_detection: bool, os_detection: bool, script_scanning: bool) -> Result<String> {
        let _permit = self.semaphore.acquire().await?;
        
        let mut cmd = Command::new("nmap");
        
        cmd.arg("-oX").arg("-"); // output XML to stdout
        cmd.arg("-T").arg(self.config.scan_intensity.to_string()); // timing template
        
        // port scanning options
        if !self.config.port_range.is_empty() {
            cmd.arg("-p").arg(&self.config.port_range);
        }
        
        // ping options
        if self.config.skip_non_pingable {
            cmd.arg("-Pn"); // skip host discovery (don't ping)
        } else {
            cmd.arg("-PE"); // use ICMP echo request for host discovery
        }
        
        if self.config.turbo_mode {
            cmd.arg("--min-rate").arg("50000");
            cmd.arg("--max-retries").arg("1");
            cmd.arg("--max-rtt-timeout").arg("50ms");
            cmd.arg("--initial-rtt-timeout").arg("100ms");
            cmd.arg("--min-rtt-timeout").arg("800ms");
            cmd.arg("--max-hostgroup").arg("1000");
            cmd.arg("--max-parallelism").arg("1000");
        }
        
        if service_detection {
            cmd.arg("-sV"); // version detection
            if self.config.version_light {
                cmd.arg("--version-light"); // faster but less detailed version detection
            }
            if self.config.turbo_mode {
                cmd.arg("--version-intensity").arg("0"); // fastest version detection
            }
        }
        
        if os_detection {
            cmd.arg("-O"); // OS detection
        }
        
        // script scanning
        if script_scanning {
            if let Some(ref scripts) = self.config.scripts {
                if !scripts.is_empty() {
                    cmd.arg("--script").arg(scripts); // custom scripts
                } else {
                    cmd.arg("-sC"); // default script scan if empty string
                }
            } else {
                cmd.arg("-sC"); // default script scan if not specified
            }
        }
        
        cmd.arg("--host-timeout").arg(format!("{}s", self.config.host_timeout));
        
        // target
        if let Some(ref target_list) = self.config.target_list_file {
            cmd.arg("-iL").arg(target_list); // input list file
        } else {
            cmd.arg(&self.config.target_range);
        }
        
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        
        debug!("Running nmap command: {:?}", cmd);
        
        let mut child = cmd.spawn()?;
        
        let stdout = child.stdout.take()
            .context("Failed to capture stdout")?;
        
        let mut output = String::new();
        let mut reader = tokio::io::BufReader::new(stdout);
        let mut line = String::new();
        
        while reader.read_line(&mut line).await? > 0 {
            output.push_str(&line);
            line.clear();
        }
        
        let status = child.wait().await?;
        
        if !status.success() {
            let stderr = child.stderr.take();
            if let Some(mut stderr) = stderr {
                let mut error_output = String::new();
                let mut stderr_reader = tokio::io::BufReader::new(&mut stderr);
                let mut error_line = String::new();
                
                while stderr_reader.read_line(&mut error_line).await? > 0 {
                    error_output.push_str(&error_line);
                    error_line.clear();
                }
                
                error!("Nmap stderr: {}", error_output);
            }
            
            return Err(anyhow::anyhow!("Nmap scan failed with exit code: {:?}", status.code()));
        }
        
        Ok(output)
    }

    async fn run_nmap_scan_services_on_hosts(&self, hosts: &[String]) -> Result<String> {
        let _permit = self.semaphore.acquire().await?;
        
        let mut cmd = Command::new("nmap");
        
        cmd.arg("-oX").arg("-"); // output XML to stdout
        cmd.arg("-T").arg(self.config.scan_intensity.to_string()); // timing template
        
        if !self.config.port_range.is_empty() {
            cmd.arg("-p").arg(&self.config.port_range);
        }
        
        // skip host discovery for service scan
        cmd.arg("-Pn");
        
        if self.config.turbo_mode {
            cmd.arg("--min-rate").arg("50000");
            cmd.arg("--max-retries").arg("1");
            cmd.arg("--max-rtt-timeout").arg("50ms");
            cmd.arg("--initial-rtt-timeout").arg("100ms");
            cmd.arg("--min-rtt-timeout").arg("800ms");
            cmd.arg("--max-hostgroup").arg("1000");
            cmd.arg("--max-parallelism").arg("1000");
        }
        
        // service detection
        if self.config.service_detection {
            cmd.arg("-sV"); // version detection
            if self.config.version_light {
                cmd.arg("--version-light"); // faster but less detailed version detection
            }
            if self.config.turbo_mode {
                cmd.arg("--version-intensity").arg("0"); // fastest version detection
            }
        }
        
        // script scanning
        if self.config.script_scanning {
            if let Some(ref scripts) = self.config.scripts {
                if !scripts.is_empty() {
                    cmd.arg("--script").arg(scripts); // custom scripts
                } else {
                    cmd.arg("-sC"); // default script scan if empty string
                }
            } else {
                cmd.arg("-sC"); // default script scan if not specified
            }
        }
        
        cmd.arg("--host-timeout").arg(format!("{}s", self.config.host_timeout));
        
        // target hosts
        for host in hosts {
            cmd.arg(host);
        }
        
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        
        debug!("Running nmap service scan command: {:?}", cmd);
        
        let mut child = cmd.spawn()?;
        
        let stdout = child.stdout.take()
            .context("Failed to capture stdout")?;
        
        let mut output = String::new();
        let mut reader = tokio::io::BufReader::new(stdout);
        let mut line = String::new();
        
        while reader.read_line(&mut line).await? > 0 {
            output.push_str(&line);
            line.clear();
        }
        
        let status = child.wait().await?;
        
        if !status.success() {
            let stderr = child.stderr.take();
            if let Some(mut stderr) = stderr {
                let mut error_output = String::new();
                let mut stderr_reader = tokio::io::BufReader::new(&mut stderr);
                let mut error_line = String::new();
                
                while stderr_reader.read_line(&mut error_line).await? > 0 {
                    error_output.push_str(&error_line);
                    error_line.clear();
                }
                
                error!("Nmap service scan stderr: {}", error_output);
            }
            
            return Err(anyhow::anyhow!("Nmap service scan failed with exit code: {:?}", status.code()));
        }
        
        Ok(output)
    }

    async fn process_nmap_results(&self, nmap_result: &NmapRun, session_id: Uuid, db: &Database) -> Result<(i32, i32, i32)> {
        let mut total_hosts = 0;
        let mut hosts_up = 0;
        let mut hosts_down = 0;

        for nmap_host in &nmap_result.hosts {
            total_hosts += 1;
            
            let host = self.parse_host(nmap_host, session_id)?;
            
            match host.status.as_str() {
                "up" => hosts_up += 1,
                "down" => hosts_down += 1,
                _ => {}
            }

            db.insert_host(&host).await?;
            
            if let Some(ports) = &nmap_host.ports {
                for nmap_port in &ports.ports {
                    let port = self.parse_port(nmap_port, host.id)?;
                    db.insert_port(&port).await?;

                    // handle port-specific scripts
                    if let Some(scripts) = &nmap_port.scripts {
                        for script in scripts {
                            let script_result = ScriptResult {
                                id: Uuid::new_v4(),
                                host_id: host.id,
                                port_id: Some(port.id),
                                script_id: script.id.clone(),
                                script_output: script.output.clone(),
                                discovered_at: Utc::now(),
                            };
                            db.insert_script_result(&script_result).await?;
                        }
                    }
                }
            }

            // handle host-level scripts
            if let Some(scripts) = &nmap_host.scripts {
                for script in scripts {
                    let script_result = ScriptResult {
                        id: Uuid::new_v4(),
                        host_id: host.id,
                        port_id: None,
                        script_id: script.id.clone(),
                        script_output: script.output.clone(),
                        discovered_at: Utc::now(),
                    };
                    db.insert_script_result(&script_result).await?;
                }
            }
        }

        Ok((total_hosts, hosts_up, hosts_down))
    }

    async fn get_hosts_with_open_ports(&self, db: &Database, session_id: Uuid) -> Result<Vec<String>> {
        let hosts = db.get_hosts_by_session(&session_id).await?;
        let mut hosts_with_open_ports = Vec::new();

        for host in hosts {
            let ports = db.get_ports_by_host(&host.id).await?;
            let has_open_ports = ports.iter().any(|p| p.state == "open");
            
            if has_open_ports {
                hosts_with_open_ports.push(host.ip_address);
            }
        }

        Ok(hosts_with_open_ports)
    }

    async fn update_services_and_scripts(&self, nmap_result: &NmapRun, db: &Database) -> Result<()> {
        // get all scan sessions to find the most recent one
        let sessions = db.get_scan_sessions().await?;
        let session = sessions.first()
            .context("No scan sessions found")?;

        for nmap_host in &nmap_result.hosts {
            let addresses = nmap_host.addresses.as_ref()
                .context("No addresses found for host")?;
            
            let ip_address = addresses.iter()
                .find(|addr| addr.addr_type == "ipv4")
                .map(|addr| addr.addr.clone())
                .context("No IPv4 address found for host")?;

            // find the host in the database
            let hosts = db.get_hosts_by_session(&session.id).await?;
            let host = hosts.into_iter()
                .find(|h| h.ip_address == ip_address)
                .context("Host not found in database")?;

            if let Some(ports) = &nmap_host.ports {
                for nmap_port in &ports.ports {
                    let port_number: i32 = nmap_port.port_id.parse()
                        .context("Failed to parse port number")?;

                    // update existing port with service information
                    let mut ports = db.get_ports_by_host(&host.id).await?;
                    if let Some(existing_port) = ports.iter_mut().find(|p| p.port_number == port_number) {
                        if let Some(service) = &nmap_port.service {
                            existing_port.service_name = service.name.clone();
                            existing_port.service_version = service.version.clone();
                            existing_port.service_product = service.product.clone();
                            existing_port.service_extrainfo = service.extra_info.clone();
                            existing_port.service_fingerprint = service.fingerprint.clone();
                        }
                        db.insert_port(existing_port).await?;

                        // handle port-specific scripts
                        if let Some(scripts) = &nmap_port.scripts {
                            for script in scripts {
                                let script_result = ScriptResult {
                                    id: Uuid::new_v4(),
                                    host_id: host.id,
                                    port_id: Some(existing_port.id),
                                    script_id: script.id.clone(),
                                    script_output: script.output.clone(),
                                    discovered_at: Utc::now(),
                                };
                                db.insert_script_result(&script_result).await?;
                            }
                        }
                    }
                }
            }

            // handle host-level scripts
            if let Some(scripts) = &nmap_host.scripts {
                for script in scripts {
                    let script_result = ScriptResult {
                        id: Uuid::new_v4(),
                        host_id: host.id,
                        port_id: None,
                        script_id: script.id.clone(),
                        script_output: script.output.clone(),
                        discovered_at: Utc::now(),
                    };
                    db.insert_script_result(&script_result).await?;
                }
            }
        }

        Ok(())
    }

    fn parse_nmap_xml_manually(&self, xml_content: &str) -> Result<NmapRun> {
        // remove DTD and other problematic XML elements
        let cleaned_xml = xml_content
            .lines()
            .filter(|line| !line.contains("<!DOCTYPE") && !line.contains("<?xml-stylesheet"))
            .collect::<Vec<_>>()
            .join("\n");
        
        let doc = Document::parse(&cleaned_xml)?;
        let mut hosts = Vec::new();

        // find all host elements
        for host_node in doc.descendants().filter(|n| n.tag_name().name() == "host") {
            let mut nmap_host = NmapHost {
                status: None,
                addresses: None,
                hostnames: None,
                ports: None,
                os: None,
                uptime: None,
                scripts: None,
            };

            // parse status
            if let Some(status_node) = host_node.children().find(|n| n.tag_name().name() == "status") {
                if let Some(state) = status_node.attribute("state") {
                    nmap_host.status = Some(NmapHostStatus {
                        state: state.to_string(),
                        reason: status_node.attribute("reason").unwrap_or("").to_string(),
                    });
                }
            }

            // parse addresses
            let mut addresses = Vec::new();
            for addr_node in host_node.children().filter(|n| n.tag_name().name() == "address") {
                if let Some(addr) = addr_node.attribute("addr") {
                    let addr_type = addr_node.attribute("addrtype").unwrap_or("ipv4").to_string();
                    let vendor = addr_node.attribute("vendor").map(|s| s.to_string());
                    addresses.push(NmapAddress {
                        addr: addr.to_string(),
                        addr_type,
                        vendor,
                    });
                }
            }
            if !addresses.is_empty() {
                nmap_host.addresses = Some(addresses);
            }

            // parse hostnames
            if let Some(hostnames_node) = host_node.children().find(|n| n.tag_name().name() == "hostnames") {
                let mut hostnames = Vec::new();
                for hostname_node in hostnames_node.children().filter(|n| n.tag_name().name() == "hostname") {
                    if let Some(name) = hostname_node.attribute("name") {
                        let hostname_type = hostname_node.attribute("type").unwrap_or("PTR").to_string();
                        hostnames.push(NmapHostname {
                            name: name.to_string(),
                            hostname_type,
                        });
                    }
                }
                if !hostnames.is_empty() {
                    nmap_host.hostnames = Some(NmapHostnames { hostnames });
                }
            }

            // parse ports
            if let Some(ports_node) = host_node.children().find(|n| n.tag_name().name() == "ports") {
                let mut ports = Vec::new();
                for port_node in ports_node.children().filter(|n| n.tag_name().name() == "port") {
                    if let Some(port_id) = port_node.attribute("portid") {
                        let protocol = port_node.attribute("protocol").unwrap_or("tcp").to_string();
                        
                        let mut nmap_port = NmapPort {
                            protocol: protocol.clone(),
                            port_id: port_id.to_string(),
                            state: None,
                            service: None,
                            scripts: None,
                        };

                        // parse port state
                        if let Some(state_node) = port_node.children().find(|n| n.tag_name().name() == "state") {
                            if let Some(state) = state_node.attribute("state") {
                                nmap_port.state = Some(NmapPortState {
                                    state: state.to_string(),
                                    reason: state_node.attribute("reason").unwrap_or("").to_string(),
                                });
                            }
                        }

                        // parse service
                        if let Some(service_node) = port_node.children().find(|n| n.tag_name().name() == "service") {
                            let name = service_node.attribute("name").map(|s| s.to_string());
                            let product = service_node.attribute("product").map(|s| s.to_string());
                            let version = service_node.attribute("version").map(|s| s.to_string());
                            let extra_info = service_node.attribute("extrainfo").map(|s| s.to_string());
                            let fingerprint = service_node.attribute("fingerprint").map(|s| s.to_string());
                            
                            nmap_port.service = Some(NmapService {
                                name,
                                product,
                                version,
                                extra_info,
                                fingerprint,
                            });
                        }

                        ports.push(nmap_port);
                    }
                }
                if !ports.is_empty() {
                    nmap_host.ports = Some(NmapPorts { ports });
                }
            }

            hosts.push(nmap_host);
        }

        // create a minimal runstats
        let run_stats = NmapRunStats {
            finished: NmapFinished {
                time_str: "".to_string(),
                summary: "".to_string(),
                elapsed: 0.0,
                exit: "success".to_string(),
            },
        };

        Ok(NmapRun {
            hosts,
            run_stats,
        })
    }

    fn parse_host(&self, nmap_host: &NmapHost, session_id: Uuid) -> Result<Host> {
        let addresses = nmap_host.addresses.as_ref()
            .context("No addresses found for host")?;

        let ip_address = addresses.iter()
            .find(|addr| addr.addr_type == "ipv4")
            .map(|addr| addr.addr.clone())
            .context("No IPv4 address found for host")?;

        let mac_address = addresses.iter()
            .find(|addr| addr.addr_type == "mac")
            .map(|addr| addr.addr.clone());

        let vendor = addresses.iter()
            .find(|addr| addr.addr_type == "mac")
            .and_then(|addr| addr.vendor.as_ref())
            .cloned();

        let hostname = nmap_host.hostnames.as_ref()
            .and_then(|hostnames| hostnames.hostnames.first())
            .map(|hostname| hostname.name.clone());

        let (os_family, os_gen, os_type) = if let Some(os) = &nmap_host.os {
            if let Some(os_matches) = &os.os_matches {
                if let Some(os_match) = os_matches.first() {
                    if let Some(os_classes) = &os_match.os_classes {
                        if let Some(os_class) = os_classes.first() {
                            (
                                Some(os_class.os_family.clone()),
                                Some(os_class.os_gen.clone()),
                                Some(os_class.os_type.clone()),
                            )
                        } else {
                            (None, None, None)
                        }
                    } else {
                        (None, None, None)
                    }
                } else {
                    (None, None, None)
                }
            } else {
                (None, None, None)
            }
        } else {
            (None, None, None)
        };

        let (uptime, last_boot) = if let Some(uptime) = &nmap_host.uptime {
            let last_boot = uptime.last_boot.as_ref()
                .and_then(|lb| chrono::DateTime::parse_from_rfc3339(lb).ok())
                .map(|dt| dt.with_timezone(&Utc));
            (Some(uptime.seconds), last_boot)
        } else {
            (None, None)
        };

        let status = if let Some(host_status) = &nmap_host.status {
            host_status.state.clone()
        } else {
            "unknown".to_string()
        };

        Ok(Host {
            id: Uuid::new_v4(),
            scan_session_id: session_id,
            ip_address,
            hostname,
            status,
            mac_address,
            vendor,
            os_family,
            os_gen,
            os_type,
            uptime,
            last_boot,
            discovered_at: Utc::now(),
        })
    }

    fn parse_port(&self, nmap_port: &NmapPort, host_id: Uuid) -> Result<Port> {
        let port_number: i32 = nmap_port.port_id.parse()
            .context("Failed to parse port number")?;

        let state = if let Some(port_state) = &nmap_port.state {
            port_state.state.clone()
        } else {
            "unknown".to_string()
        };

        let (service_name, service_version, service_product, service_extrainfo, service_fingerprint) = 
            if let Some(service) = &nmap_port.service {
                (
                    service.name.clone(),
                    service.version.clone(),
                    service.product.clone(),
                    service.extra_info.clone(),
                    service.fingerprint.clone(),
                )
            } else {
                (None, None, None, None, None)
            };

        Ok(Port {
            id: Uuid::new_v4(),
            host_id,
            port_number,
            protocol: nmap_port.protocol.clone(),
            state,
            service_name,
            service_version,
            service_product,
            service_extrainfo,
            service_fingerprint,
            discovered_at: Utc::now(),
        })
    }
}
