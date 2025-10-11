use crate::config::ScanConfig;
use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::process::Stdio;
use tokio::io::AsyncBufReadExt;
use tokio::process::Command;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZmapResult {
    pub ip_address: String,
    pub timestamp: u64,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZmapConfig {
    pub target_range: String,
    pub port: u16,
    pub rate: u32,
    pub max_hosts: Option<u32>,
    /// csv, json
    pub output_format: String,
    pub interface: Option<String>,
    pub source_ip: Option<String>,
    pub threads: Option<u32>,
}

impl Default for ZmapConfig {
    fn default() -> Self {
        Self {
            target_range: "0.0.0.0/0".to_string(),
            port: 80,
            rate: 10000,
            max_hosts: None,
            output_format: "csv".to_string(),
            interface: None,
            source_ip: None,
            threads: Some(1),
        }
    }
}

pub struct ZmapScanner {
    config: ZmapConfig,
}

impl ZmapScanner {
    pub fn new(config: ZmapConfig) -> Self {
        Self { config }
    }

    pub async fn scan_network(&self) -> Result<Vec<ZmapResult>> {
        info!("Starting zmap scan for range: {} on port {}", self.config.target_range, self.config.port);
        
        let mut cmd = Command::new("zmap");
        
        // basic zmap options
        cmd.arg("-p").arg(self.config.port.to_string());
        cmd.arg("-r").arg(self.config.rate.to_string());
        cmd.arg("-o").arg("-"); // output to stdout
        
        // target range
        cmd.arg(self.config.target_range.clone());
        
        // optional parameters
        if let Some(max_hosts) = self.config.max_hosts {
            cmd.arg("-n").arg(max_hosts.to_string());
        }
        
        if let Some(interface) = &self.config.interface {
            cmd.arg("-i").arg(interface);
        }
        
        if let Some(source_ip) = &self.config.source_ip {
            cmd.arg("-S").arg(source_ip);
        }
        
        if let Some(threads) = self.config.threads {
            cmd.arg("-T").arg(threads.to_string());
        }
        
        // use only saddr field which is always available
        cmd.arg("--output-fields=saddr");
        
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        
        debug!("Running zmap command: {:?}", cmd);
        
        let mut child = cmd.spawn()?;
        
        let stdout = child.stdout.take()
            .context("Failed to capture stdout")?;
        
        let mut results = Vec::new();
        let mut reader = tokio::io::BufReader::new(stdout);
        let mut line = String::new();
        
        while reader.read_line(&mut line).await? > 0 {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                match self.parse_zmap_output_line(trimmed) {
                    Ok(result) => results.push(result),
                    Err(e) => {
                        warn!("Failed to parse zmap output line '{}': {}", trimmed, e);
                    }
                }
            }
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
                
                warn!("Zmap stderr: {}", error_output);
            }
            
            return Err(anyhow::anyhow!("Zmap scan failed with exit code: {:?}", status.code()));
        }
        
        info!("Zmap scan completed: {} hosts found", results.len());
        Ok(results)
    }

    fn parse_zmap_output_line(&self, line: &str) -> Result<ZmapResult> {
        // just extract the IP address
        let ip_address = line.trim().to_string();
        
        // basic IP validation
        if ip_address.is_empty() {
            return Err(anyhow::anyhow!("Empty IP address"));
        }
        
        Ok(ZmapResult {
            ip_address,
            timestamp: Utc::now().timestamp() as u64,
            success: true,
        })
    }

    pub async fn scan_network_to_file(&self, output_file: &str) -> Result<Vec<ZmapResult>> {
        info!("Starting zmap scan for range: {} on port {} -> {}", 
              self.config.target_range, self.config.port, output_file);
        
        let mut cmd = Command::new("zmap");
        
        // basic zmap options
        cmd.arg("-p").arg(self.config.port.to_string());
        cmd.arg("-r").arg(self.config.rate.to_string());
        cmd.arg("-o").arg(output_file);
        
        // target range
        cmd.arg(self.config.target_range.clone());
        
        // optional parameters
        if let Some(max_hosts) = self.config.max_hosts {
            cmd.arg("-n").arg(max_hosts.to_string());
        }
        
        if let Some(interface) = &self.config.interface {
            cmd.arg("-i").arg(interface);
        }
        
        if let Some(source_ip) = &self.config.source_ip {
            cmd.arg("-S").arg(source_ip);
        }
        
        if let Some(threads) = self.config.threads {
            cmd.arg("-T").arg(threads.to_string());
        }
        
        // use only saddr field which is always available
        cmd.arg("--output-fields=saddr");
        
        cmd.stderr(Stdio::piped());
        
        debug!("Running zmap command: {:?}", cmd);
        
        let mut child = cmd.spawn()?;
        
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
                
                warn!("Zmap stderr: {}", error_output);
            }
            
            return Err(anyhow::anyhow!("Zmap scan failed with exit code: {:?}", status.code()));
        }
        
        // read results from file
        let results = self.read_results_from_file(output_file).await?;
        
        info!("Zmap scan completed: {} hosts found", results.len());
        Ok(results)
    }

    async fn read_results_from_file(&self, file_path: &str) -> Result<Vec<ZmapResult>> {
        let contents = tokio::fs::read_to_string(file_path).await?;
        let mut results = Vec::new();
        
        for line in contents.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                match self.parse_zmap_output_line(trimmed) {
                    Ok(result) => results.push(result),
                    Err(e) => {
                        warn!("Failed to parse zmap output line '{}': {}", trimmed, e);
                    }
                }
            }
        }
        
        Ok(results)
    }
}

impl ZmapConfig {
    pub fn from_scan_config(scan_config: &ScanConfig) -> Self {
        let mut zmap_config = Self::default();
        
        // extract port from port range (use first port if range specified)
        if let Some(first_port) = scan_config.port_range.split(',').next() {
            if let Ok(port) = first_port.parse::<u16>() {
                zmap_config.port = port;
            }
        }
        
        // set target range
        zmap_config.target_range = scan_config.target_range.clone();
        
        // adjust rate based on scan intensity
        zmap_config.rate = match scan_config.scan_intensity {
            0 => 1000,
            1 => 5000,
            2 => 10000,
            3 => 20000,
            4 => 50000,
            5 => 100000,
            _ => 10000,
        };
        
        zmap_config
    }
    
    pub fn validate(&self) -> Result<()> {
        if self.rate == 0 {
            return Err(anyhow::anyhow!("Rate must be greater than 0"));
        }
        
        if self.port == 0 {
            return Err(anyhow::anyhow!("Port must be greater than 0"));
        }
        
        if self.target_range.is_empty() {
            return Err(anyhow::anyhow!("Target range cannot be empty"));
        }
        
        Ok(())
    }
}
