use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(name = "portshit")]
#[command(about = "A comprehensive network scanner that wraps around nmap")]
#[command(version = "0.1.0")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// run a network scan
    Scan {
        /// IP range to scan (ex. "192.168.1.0/24" or "10.0.0.1-254")
        #[arg(short, long)]
        target: Option<String>,

        /// file containing list of targets (one per line)
        #[arg(short = 'L', long)]
        target_list: Option<String>,

        /// port range to scan (ex. "1-1000" or "22,80,443,8080")
        #[arg(short, long)]
        ports: Option<String>,

        /// skip port scanning on hosts that don't respond to ping
        #[arg(long)]
        skip_non_pingable: Option<bool>,

        /// scan intensity (0-5, where 5 is most aggressive)
        #[arg(short, long)]
        intensity: Option<u8>,

        /// enable OS detection
        #[arg(long)]
        os_detection: Option<bool>,

        /// enable service version detection
        #[arg(long)]
        service_detection: Option<bool>,

        /// enable script scanning
        #[arg(long)]
        script_scanning: Option<bool>,

        /// use version-light for service detection
        #[arg(long)]
        version_light: Option<bool>,

        /// custom nmap scripts to run
        #[arg(long)]
        scripts: Option<String>,

        /// turbo mode - maximum speed optimizations but less reliable
        #[arg(long)]
        turbo: Option<bool>,

        /// skip all database operations
        #[arg(long)]
        no_db: Option<bool>,

        /// use two-pass scanning
        #[arg(long)]
        two_pass: Option<bool>,

        /// use zmap for initial host discovery
        #[arg(long)]
        zmap_discovery: Option<bool>,

        /// zmap scan rate (packets per second)
        #[arg(long)]
        zmap_rate: Option<u32>,

        /// zmap interface to use
        #[arg(long)]
        zmap_interface: Option<String>,

        /// zmap source IP address
        #[arg(long)]
        zmap_source_ip: Option<String>,

        /// database file path
        #[arg(short = 'D', long)]
        database: Option<String>,

        /// maximum number of concurrent scans
        #[arg(long)]
        max_concurrent: Option<usize>,

        /// timeout for individual host scans in seconds
        #[arg(long)]
        host_timeout: Option<u64>,

        /// force parallel chunked scanning
        #[arg(long)]
        force_parallel: Option<bool>,

        /// chunk size for parallel scanning (CIDR notation)
        #[arg(long)]
        chunk_size: Option<u8>,

        /// use 3-stage pipeline scanning (discovery -> service -> camera)
        #[arg(long)]
        pipeline: Option<bool>,

        /// number of discovery threads in pipeline
        #[arg(long)]
        discovery_threads: Option<usize>,

        /// number of service detection threads in pipeline
        #[arg(long)]
        service_threads: Option<usize>,

        /// number of camera capture threads in pipeline
        #[arg(long)]
        camera_threads: Option<usize>,

        /// resume a previous scan session
        #[arg(long)]
        resume_session: Option<String>,

        /// camera authentication string for RTSP streams (format: "username:password")
        #[arg(long)]
        camera_auth: Option<String>,
    },

    /// list previous scan sessions
    List {
        /// show detailed information
        #[arg(short, long)]
        detailed: bool,

        /// limit number of results
        #[arg(short, long)]
        limit: Option<usize>,

        /// database file path
        #[arg(short = 'D', long)]
        database: Option<String>,
    },

    /// show details of a specific scan session
    Show {
        /// scan session ID
        session_id: String,

        /// show only hosts
        #[arg(long)]
        hosts_only: bool,

        /// show only open ports
        #[arg(long)]
        open_ports_only: bool,

        /// database file path
        #[arg(short = 'D', long)]
        database: Option<String>,
    },

    /// export scan results
    Export {
        /// scan session ID
        session_id: String,

        /// output format (json, csv)
        #[arg(short, long, default_value = "json")]
        format: String,

        /// output file path
        #[arg(short, long)]
        output: Option<String>,
    },

    /// initialize database
    Init {
        /// database file path
        #[arg(short = 'D', long)]
        database: Option<String>,
    },

    /// show camera screenshots
    Cameras {
        /// scan session ID
        session_id: String,

        /// database file path
        #[arg(short = 'D', long)]
        database: Option<String>,
    },

    /// manage device catalog metadata
    Device {
        #[command(subcommand)]
        device_command: DeviceCommands,
    },

    /// manage subnet catalog
    Subnet {
        #[command(subcommand)]
        subnet_command: SubnetCommands,
    },

    /// run the webserver API
    Server {
        /// database file path
        #[arg(short = 'D', long)]
        database: Option<String>,

        /// API key for authentication (defaults to environment variable API_KEY or generates one)
        #[arg(long)]
        api_key: Option<String>,

        /// server bind address (default: 127.0.0.1:8080)
        #[arg(long, default_value = "127.0.0.1:8080")]
        bind: String,
    },
}

#[derive(Subcommand)]
pub enum DeviceCommands {
    /// set or update device catalog metadata
    Set {
        /// IP address of the device
        ip_address: String,

        /// device name
        #[arg(long)]
        name: Option<String>,

        /// device description
        #[arg(long)]
        description: Option<String>,

        /// campus name
        #[arg(long)]
        campus: Option<String>,

        /// latitude (for cameras, in decimal degrees)
        #[arg(long)]
        latitude: Option<f64>,

        /// longitude (for cameras, in decimal degrees)
        #[arg(long)]
        longitude: Option<f64>,

        /// floor number (for cameras)
        #[arg(long)]
        floor: Option<i32>,

        /// database file path
        #[arg(short = 'D', long)]
        database: Option<String>,
    },

    /// show device catalog metadata for an IP
    Show {
        /// IP address of the device
        ip_address: String,

        /// database file path
        #[arg(short = 'D', long)]
        database: Option<String>,
    },

    /// show history of changes for an IP address
    History {
        /// IP address of the device
        ip_address: String,

        /// database file path
        #[arg(short = 'D', long)]
        database: Option<String>,
    },

    /// list all cataloged devices
    List {
        /// database file path
        #[arg(short = 'D', long)]
        database: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum SubnetCommands {
    /// detect subnets from all discovered IP addresses
    Detect {
        /// database file path
        #[arg(short = 'D', long)]
        database: Option<String>,
    },

    /// list all detected subnets
    List {
        /// filter by status (in_use, unused, deprecated)
        #[arg(long)]
        status: Option<String>,

        /// database file path
        #[arg(short = 'D', long)]
        database: Option<String>,
    },

    /// show details for a specific subnet
    Show {
        /// CIDR notation (e.g., "10.1.2.0/24")
        cidr: String,

        /// database file path
        #[arg(short = 'D', long)]
        database: Option<String>,
    },

    /// set or update subnet metadata
    Set {
        /// CIDR notation (e.g., "10.1.2.0/24")
        cidr: String,

        /// subnet name
        #[arg(long)]
        name: Option<String>,

        /// campus name
        #[arg(long)]
        campus: Option<String>,

        /// database file path
        #[arg(short = 'D', long)]
        database: Option<String>,
    },

    /// change subnet CIDR (rename or merge)
    Change {
        /// old CIDR notation
        old_cidr: String,

        /// new CIDR notation
        new_cidr: String,

        /// database file path
        #[arg(short = 'D', long)]
        database: Option<String>,
    },

    /// delete a subnet catalog entry
    Delete {
        /// CIDR notation to delete
        cidr: String,

        /// database file path
        #[arg(short = 'D', long)]
        database: Option<String>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HostSummary {
    pub ip_address: String,
    pub hostname: Option<String>,
    pub status: String,
    pub open_ports: i32,
    pub services: Vec<String>,
    pub os_info: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PortSummary {
    pub port_number: i32,
    pub protocol: String,
    pub state: String,
    pub service_name: Option<String>,
    pub service_version: Option<String>,
    pub service_product: Option<String>,
}
