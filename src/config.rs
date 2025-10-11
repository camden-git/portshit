use anyhow;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// IP range to scan (ex. "192.168.1.0/24" or "10.0.0.1-254")
    pub target_range: String,
    /// file containing list of targets (one per line)
    pub target_list_file: Option<String>,
    /// skip port scanning on hosts that don't respond to ping
    pub skip_non_pingable: bool,
    /// port range to scan (ex. "1-1000" or "22,80,443,8080")
    pub port_range: String,
    /// scan intensity (0-5, where 5 is most aggressive)
    pub scan_intensity: u8,
    /// enable OS detection
    pub os_detection: bool,
    /// enable service version detection
    pub service_detection: bool,
    /// enable script scanning
    pub script_scanning: bool,
    /// use version-light for service detection
    pub version_light: bool,
    /// custom nmap scripts to run
    pub scripts: Option<String>,
    /// turbo mode - maximum speed optimizations but less reliable
    pub turbo_mode: bool,
    /// use two-pass scanning
    pub two_pass_scanning: bool,
    /// use zmap for initial host discovery
    pub use_zmap_discovery: bool,
    /// zmap scan rate (packets per second)
    pub zmap_rate: u32,
    /// zmap interface to use
    pub zmap_interface: Option<String>,
    /// zmap source IP address
    pub zmap_source_ip: Option<String>,
    /// database file path
    pub database_path: String,
    /// resume a previous scan session
    pub resume_session: Option<String>,
    /// maximum number of concurrent scans
    pub max_concurrent_scans: usize,
    /// timeout for individual host scans in seconds
    pub host_timeout: u64,
    /// camera authentication string for RTSP streams (format: "username:password")
    pub camera_auth: String,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            target_range: "192.168.1.0/24".to_string(),
            target_list_file: None,
            skip_non_pingable: true,
            port_range: "1-1000".to_string(),
            scan_intensity: 3,
            os_detection: false,
            service_detection: true,
            script_scanning: false,
            version_light: false,
            scripts: None,
            turbo_mode: false,
            two_pass_scanning: true,
            use_zmap_discovery: false,
            zmap_rate: 10000,
            zmap_interface: None,
            zmap_source_ip: None,
            database_path: "scan_results.db".to_string(),
            resume_session: None,
            max_concurrent_scans: 10,
            host_timeout: 15,
            camera_auth: "root:osss15%21".to_string(),
        }
    }
}

impl ScanConfig {
    pub fn from_env() -> Self {
        let mut config = Self::default();
        
        if let Ok(target) = env::var("NMAP_TARGET_RANGE") {
            config.target_range = target;
        }
        
        if let Ok(target_list) = env::var("NMAP_TARGET_LIST_FILE") {
            config.target_list_file = Some(target_list);
        }
        
        if let Ok(skip_ping) = env::var("NMAP_SKIP_NON_PINGABLE") {
            config.skip_non_pingable = skip_ping.parse().unwrap_or(true);
        }
        
        if let Ok(ports) = env::var("NMAP_PORT_RANGE") {
            config.port_range = ports;
        }
        
        if let Ok(intensity) = env::var("NMAP_SCAN_INTENSITY") {
            config.scan_intensity = intensity.parse().unwrap_or(3);
        }
        
        if let Ok(os_detect) = env::var("NMAP_OS_DETECTION") {
            config.os_detection = os_detect.parse().unwrap_or(false);
        }
        
        if let Ok(service_detect) = env::var("NMAP_SERVICE_DETECTION") {
            config.service_detection = service_detect.parse().unwrap_or(true);
        }
        
        if let Ok(script_scan) = env::var("NMAP_SCRIPT_SCANNING") {
            config.script_scanning = script_scan.parse().unwrap_or(false);
        }
        
        if let Ok(version_light) = env::var("NMAP_VERSION_LIGHT") {
            config.version_light = version_light.parse().unwrap_or(false);
        }
        
        if let Ok(scripts) = env::var("NMAP_SCRIPTS") {
            config.scripts = Some(scripts);
        }
        
        if let Ok(turbo) = env::var("NMAP_TURBO_MODE") {
            config.turbo_mode = turbo.parse().unwrap_or(false);
        }
        
        if let Ok(two_pass) = env::var("NMAP_TWO_PASS_SCANNING") {
            config.two_pass_scanning = two_pass.parse().unwrap_or(true);
        }
        
        if let Ok(use_zmap) = env::var("NMAP_USE_ZMAP_DISCOVERY") {
            config.use_zmap_discovery = use_zmap.parse().unwrap_or(false);
        }
        
        if let Ok(zmap_rate) = env::var("NMAP_ZMAP_RATE") {
            config.zmap_rate = zmap_rate.parse().unwrap_or(10000);
        }
        
        if let Ok(zmap_interface) = env::var("NMAP_ZMAP_INTERFACE") {
            config.zmap_interface = Some(zmap_interface);
        }
        
        if let Ok(zmap_source_ip) = env::var("NMAP_ZMAP_SOURCE_IP") {
            config.zmap_source_ip = Some(zmap_source_ip);
        }
        
        if let Ok(db_path) = env::var("NMAP_DATABASE_PATH") {
            config.database_path = db_path;
        }
        
        if let Ok(max_concurrent) = env::var("NMAP_MAX_CONCURRENT_SCANS") {
            config.max_concurrent_scans = max_concurrent.parse().unwrap_or(10);
        }
        
        if let Ok(timeout) = env::var("NMAP_HOST_TIMEOUT") {
            config.host_timeout = timeout.parse().unwrap_or(300);
        }
        
        if let Ok(camera_auth) = env::var("NMAP_CAMERA_AUTH") {
            config.camera_auth = camera_auth;
        }
        
        config
    }
    
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.scan_intensity > 5 {
            return Err(anyhow::anyhow!("Scan intensity must be between 0 and 5"));
        }
        
        if self.max_concurrent_scans == 0 {
            return Err(anyhow::anyhow!("Max concurrent scans must be greater than 0"));
        }
        
        if self.host_timeout == 0 {
            return Err(anyhow::anyhow!("Host timeout must be greater than 0"));
        }
        
        // TODO: improve
        if self.target_range.is_empty() {
            return Err(anyhow::anyhow!("Target range cannot be empty"));
        }
        
        Ok(())
    }
}
