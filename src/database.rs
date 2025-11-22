use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{sqlite::SqlitePool, Row};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSession {
    pub id: Uuid,
    pub target_range: String,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub total_hosts: i32,
    pub hosts_up: i32,
    pub hosts_down: i32,
    pub config_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub id: Uuid,
    pub scan_session_id: Uuid,
    pub ip_address: String,
    pub hostname: Option<String>,
    /// Host status: "up", "down", or "filtered"
    pub status: String,
    pub mac_address: Option<String>,
    pub vendor: Option<String>,
    pub os_family: Option<String>,
    pub os_gen: Option<String>,
    pub os_type: Option<String>,
    pub uptime: Option<i64>,
    pub last_boot: Option<DateTime<Utc>>,
    pub discovered_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Port {
    pub id: Uuid,
    pub host_id: Uuid,
    pub port_number: i32,
    /// Protocol: "tcp" or "udp"
    pub protocol: String,
    /// Port state: "open", "closed", "filtered", "unfiltered", "open|filtered", or "closed|filtered"
    pub state: String,
    pub service_name: Option<String>,
    pub service_version: Option<String>,
    pub service_product: Option<String>,
    pub service_extrainfo: Option<String>,
    pub service_fingerprint: Option<String>,
    pub discovered_at: DateTime<Utc>,
}

/// Represents a script execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptResult {
    pub id: Uuid,
    pub host_id: Uuid,
    pub port_id: Option<Uuid>,
    pub script_id: String,
    pub script_output: String,
    pub discovered_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CameraScreenshot {
    pub id: Uuid,
    pub scan_session_id: Uuid,
    pub host_ip: String,
    pub rtsp_url: String,
    pub screenshot_path: String,
    pub captured_at: DateTime<Utc>,
    /// None for successful captures, Some(error) for failures
    pub error_message: Option<String>,
    /// Camera index (1, 2, 3, etc. for individual cameras, or None for default/single camera)
    pub camera_index: Option<i32>,
    /// Camera type: "individual" for single camera views, "grid" for combined grid view
    pub camera_type: Option<String>,
}

/// Represents scan progress tracking for a chunk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub id: Uuid,
    pub scan_session_id: Uuid,
    pub chunk_range: String,
    /// Stage: "discovery", "service", or "camera"
    pub stage: String,
    /// Status: "pending", "in_progress", "completed", or "failed"
    pub status: String,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
}

/// Represents device catalog metadata (persistent across scan sessions)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCatalog {
    pub ip_address: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub campus_name: Option<String>,
    /// For cameras: latitude (decimal degrees)
    pub latitude: Option<f64>,
    /// For cameras: longitude (decimal degrees)
    pub longitude: Option<f64>,
    /// For cameras: floor number within building
    pub floor_number: Option<i32>,
    pub updated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// Represents historical snapshot of host data from a scan session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostHistory {
    pub id: Uuid,
    pub ip_address: String,
    pub scan_session_id: Uuid,
    pub hostname: Option<String>,
    pub status: String,
    pub mac_address: Option<String>,
    pub vendor: Option<String>,
    pub os_family: Option<String>,
    pub os_gen: Option<String>,
    pub os_type: Option<String>,
    pub uptime: Option<i64>,
    pub last_boot: Option<DateTime<Utc>>,
    /// JSON snapshot of open ports at this time
    pub ports_snapshot: String,
    /// Timestamp when this snapshot was created
    pub snapshot_at: DateTime<Utc>,
}

/// Represents a detected subnet in the network catalog
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubnetCatalog {
    /// CIDR notation (e.g., "10.1.2.0/24")
    pub cidr: String,
    /// Optional custom name for the subnet
    pub name: Option<String>,
    /// Optional campus name
    pub campus_name: Option<String>,
    /// Subnet mask size (16, 20, 22, 24, etc.)
    pub subnet_size: i32,
    /// Total number of IP addresses in this subnet
    pub total_ips: i64,
    /// Number of IPs that have had discovered hosts
    pub active_ips: i64,
    /// Utilization percentage (active_ips / total_ips * 100)
    pub utilization_percent: f64,
    /// Status: "in_use", "unused", "deprecated"
    pub status: String,
    /// Timestamp when subnet was first discovered
    pub first_discovered: DateTime<Utc>,
    /// Timestamp of most recent discovery of hosts in this subnet
    pub last_seen: DateTime<Utc>,
    /// Number of scan sessions that found hosts in this subnet
    pub discovery_sessions: i32,
}

/// Database connection and operations manager
#[derive(Clone)]
pub struct Database {
    pool: SqlitePool,
}

/// Error type for database operations
#[derive(Debug, thiserror::Error)]
pub enum DatabaseError {
    #[error("SQLx error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("UUID parsing error: {0}")]
    Uuid(#[from] uuid::Error),
    #[error("DateTime parsing error: {0}")]
    DateTime(#[from] chrono::ParseError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl Database {
    /// Creates a new database connection and initializes the schema
    ///
    /// # Arguments
    /// * `database_path` - Path to the SQLite database file
    ///
    /// # Errors
    /// Returns an error if the database cannot be created or connected to
    pub async fn new(database_path: &str) -> Result<Self, DatabaseError> {
        let path = std::path::Path::new(database_path);

        // Create directory if it doesn't exist
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Create the database file if it doesn't exist
        if !path.exists() {
            std::fs::File::create(database_path)?;
        }

        let pool = SqlitePool::connect(&format!("sqlite://{}", database_path)).await?;
        let db = Self { pool };
        db.create_tables().await?;
        Ok(db)
    }

    /// Creates all required database tables and indexes
    async fn create_tables(&self) -> Result<(), DatabaseError> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS scan_sessions (
                id TEXT PRIMARY KEY,
                target_range TEXT NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT,
                total_hosts INTEGER DEFAULT 0,
                hosts_up INTEGER DEFAULT 0,
                hosts_down INTEGER DEFAULT 0,
                config_json TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS hosts (
                id TEXT PRIMARY KEY,
                scan_session_id TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                hostname TEXT,
                status TEXT NOT NULL,
                mac_address TEXT,
                vendor TEXT,
                os_family TEXT,
                os_gen TEXT,
                os_type TEXT,
                uptime INTEGER,
                last_boot TEXT,
                discovered_at TEXT NOT NULL,
                FOREIGN KEY (scan_session_id) REFERENCES scan_sessions (id)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS ports (
                id TEXT PRIMARY KEY,
                host_id TEXT NOT NULL,
                port_number INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                state TEXT NOT NULL,
                service_name TEXT,
                service_version TEXT,
                service_product TEXT,
                service_extrainfo TEXT,
                service_fingerprint TEXT,
                discovered_at TEXT NOT NULL,
                FOREIGN KEY (host_id) REFERENCES hosts (id),
                UNIQUE(host_id, port_number, protocol)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS script_results (
                id TEXT PRIMARY KEY,
                host_id TEXT NOT NULL,
                port_id TEXT,
                script_id TEXT NOT NULL,
                script_output TEXT NOT NULL,
                discovered_at TEXT NOT NULL,
                FOREIGN KEY (host_id) REFERENCES hosts (id),
                FOREIGN KEY (port_id) REFERENCES ports (id)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS camera_screenshots (
                id TEXT PRIMARY KEY,
                scan_session_id TEXT NOT NULL,
                host_ip TEXT NOT NULL,
                rtsp_url TEXT NOT NULL,
                screenshot_path TEXT NOT NULL,
                captured_at TEXT NOT NULL,
                error_message TEXT,
                camera_index INTEGER,
                camera_type TEXT,
                FOREIGN KEY (scan_session_id) REFERENCES scan_sessions (id),
                UNIQUE(scan_session_id, host_ip, rtsp_url)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Add new columns if they don't exist (for migration compatibility)
        sqlx::query(
            r#"
            ALTER TABLE camera_screenshots ADD COLUMN camera_index INTEGER
            "#,
        )
        .execute(&self.pool)
        .await
        .ok(); // Ignore error if column already exists

        sqlx::query(
            r#"
            ALTER TABLE camera_screenshots ADD COLUMN camera_type TEXT
            "#,
        )
        .execute(&self.pool)
        .await
        .ok(); // Ignore error if column already exists

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS scan_progress (
                id TEXT PRIMARY KEY,
                scan_session_id TEXT NOT NULL,
                chunk_range TEXT NOT NULL,
                stage TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                error_message TEXT,
                FOREIGN KEY (scan_session_id) REFERENCES scan_sessions (id)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Device catalog table - persistent metadata about devices
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS device_catalog (
                ip_address TEXT PRIMARY KEY,
                name TEXT,
                description TEXT,
                campus_name TEXT,
                latitude REAL,
                longitude REAL,
                floor_number INTEGER,
                updated_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Host history table - tracks changes to IP addresses over time
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS host_history (
                id TEXT PRIMARY KEY,
                ip_address TEXT NOT NULL,
                scan_session_id TEXT NOT NULL,
                hostname TEXT,
                status TEXT NOT NULL,
                mac_address TEXT,
                vendor TEXT,
                os_family TEXT,
                os_gen TEXT,
                os_type TEXT,
                uptime INTEGER,
                last_boot TEXT,
                ports_snapshot TEXT NOT NULL,
                snapshot_at TEXT NOT NULL,
                FOREIGN KEY (scan_session_id) REFERENCES scan_sessions (id)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Create indexes for better query performance
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip_address)")
            .execute(&self.pool)
            .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_hosts_session ON hosts(scan_session_id)")
            .execute(&self.pool)
            .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id)")
            .execute(&self.pool)
            .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_ports_number ON ports(port_number)")
            .execute(&self.pool)
            .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_host_history_ip ON host_history(ip_address)")
            .execute(&self.pool)
            .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_host_history_session ON host_history(scan_session_id)")
            .execute(&self.pool)
            .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_host_history_snapshot_at ON host_history(snapshot_at)")
            .execute(&self.pool)
            .await?;

        // Subnet catalog table - tracks detected subnets
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS subnet_catalog (
                cidr TEXT PRIMARY KEY,
                name TEXT,
                campus_name TEXT,
                subnet_size INTEGER NOT NULL,
                total_ips INTEGER NOT NULL,
                active_ips INTEGER NOT NULL,
                utilization_percent REAL NOT NULL,
                status TEXT NOT NULL,
                first_discovered TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                discovery_sessions INTEGER DEFAULT 0
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_subnet_catalog_status ON subnet_catalog(status)")
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Creates a new scan session in the database
    pub async fn create_scan_session(&self, session: &ScanSession) -> Result<(), DatabaseError> {
        sqlx::query(
            r#"
            INSERT INTO scan_sessions (id, target_range, start_time, end_time, total_hosts, hosts_up, hosts_down, config_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(session.id.to_string())
        .bind(&session.target_range)
        .bind(session.start_time.to_rfc3339())
        .bind(session.end_time.map(|dt| dt.to_rfc3339()))
        .bind(session.total_hosts)
        .bind(session.hosts_up)
        .bind(session.hosts_down)
        .bind(&session.config_json)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Updates an existing scan session
    pub async fn update_scan_session(&self, session: &ScanSession) -> Result<(), DatabaseError> {
        sqlx::query(
            r#"
            UPDATE scan_sessions 
            SET end_time = ?, total_hosts = ?, hosts_up = ?, hosts_down = ?
            WHERE id = ?
            "#,
        )
        .bind(session.end_time.map(|dt| dt.to_rfc3339()))
        .bind(session.total_hosts)
        .bind(session.hosts_up)
        .bind(session.hosts_down)
        .bind(session.id.to_string())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Inserts a new host into the database
    pub async fn insert_host(&self, host: &Host) -> Result<(), DatabaseError> {
        sqlx::query(
            r#"
            INSERT INTO hosts (id, scan_session_id, ip_address, hostname, status, mac_address, vendor, os_family, os_gen, os_type, uptime, last_boot, discovered_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(host.id.to_string())
        .bind(host.scan_session_id.to_string())
        .bind(&host.ip_address)
        .bind(&host.hostname)
        .bind(&host.status)
        .bind(&host.mac_address)
        .bind(&host.vendor)
        .bind(&host.os_family)
        .bind(&host.os_gen)
        .bind(&host.os_type)
        .bind(host.uptime)
        .bind(host.last_boot.map(|dt| dt.to_rfc3339()))
        .bind(host.discovered_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Inserts or replaces a port in the database
    pub async fn insert_port(&self, port: &Port) -> Result<(), DatabaseError> {
        sqlx::query(
            r#"
            INSERT OR REPLACE INTO ports (id, host_id, port_number, protocol, state, service_name, service_version, service_product, service_extrainfo, service_fingerprint, discovered_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(port.id.to_string())
        .bind(port.host_id.to_string())
        .bind(port.port_number)
        .bind(&port.protocol)
        .bind(&port.state)
        .bind(&port.service_name)
        .bind(&port.service_version)
        .bind(&port.service_product)
        .bind(&port.service_extrainfo)
        .bind(&port.service_fingerprint)
        .bind(port.discovered_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Inserts a script result into the database
    pub async fn insert_script_result(
        &self,
        script_result: &ScriptResult,
    ) -> Result<(), DatabaseError> {
        sqlx::query(
            r#"
            INSERT INTO script_results (id, host_id, port_id, script_id, script_output, discovered_at)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(script_result.id.to_string())
        .bind(script_result.host_id.to_string())
        .bind(script_result.port_id.map(|id| id.to_string()))
        .bind(&script_result.script_id)
        .bind(&script_result.script_output)
        .bind(script_result.discovered_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Inserts a camera screenshot into the database
    pub async fn insert_camera_screenshot(
        &self,
        screenshot: &CameraScreenshot,
    ) -> Result<(), DatabaseError> {
        sqlx::query(
            r#"
            INSERT OR IGNORE INTO camera_screenshots (id, scan_session_id, host_ip, rtsp_url, screenshot_path, captured_at, error_message, camera_index, camera_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(screenshot.id.to_string())
        .bind(screenshot.scan_session_id.to_string())
        .bind(&screenshot.host_ip)
        .bind(&screenshot.rtsp_url)
        .bind(&screenshot.screenshot_path)
        .bind(screenshot.captured_at.to_rfc3339())
        .bind(&screenshot.error_message)
        .bind(screenshot.camera_index)
        .bind(&screenshot.camera_type)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Retrieves all camera screenshots for a given scan session
    pub async fn get_camera_screenshots_by_session(
        &self,
        session_id: &Uuid,
    ) -> Result<Vec<CameraScreenshot>, DatabaseError> {
        let rows = sqlx::query(
            "SELECT * FROM camera_screenshots WHERE scan_session_id = ? ORDER BY captured_at DESC",
        )
        .bind(session_id.to_string())
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| Self::row_to_camera_screenshot(&row))
            .collect()
    }

    /// Retrieves all camera screenshots for a given host IP address
    pub async fn get_camera_screenshots_by_host_ip(
        &self,
        host_ip: &str,
    ) -> Result<Vec<CameraScreenshot>, DatabaseError> {
        let rows = sqlx::query(
            "SELECT * FROM camera_screenshots WHERE host_ip = ? ORDER BY captured_at DESC",
        )
        .bind(host_ip)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| Self::row_to_camera_screenshot(&row))
            .collect()
    }

    /// Retrieves a camera screenshot by its ID
    pub async fn get_camera_screenshot_by_id(
        &self,
        screenshot_id: &Uuid,
    ) -> Result<Option<CameraScreenshot>, DatabaseError> {
        let row = sqlx::query("SELECT * FROM camera_screenshots WHERE id = ?")
            .bind(screenshot_id.to_string())
            .fetch_optional(&self.pool)
            .await?;

        row.map(|r| Self::row_to_camera_screenshot(&r)).transpose()
    }

    /// Retrieves all unique cameras (RTSP URLs) for a given host IP address
    /// Returns the most recent screenshot entry for each unique RTSP URL
    pub async fn get_cameras_by_host_ip(
        &self,
        host_ip: &str,
    ) -> Result<Vec<CameraScreenshot>, DatabaseError> {
        // Get the most recent screenshot for each unique RTSP URL
        let rows = sqlx::query(
            r#"
            SELECT * FROM camera_screenshots 
            WHERE host_ip = ? 
            AND id IN (
                SELECT MAX(id) 
                FROM camera_screenshots 
                WHERE host_ip = ? 
                GROUP BY rtsp_url
            )
            ORDER BY camera_index ASC NULLS LAST, captured_at DESC
            "#,
        )
        .bind(host_ip)
        .bind(host_ip)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| Self::row_to_camera_screenshot(&row))
            .collect()
    }

    /// Checks if a camera screenshot exists for a given host in a session
    pub async fn has_camera_screenshot_for_host(
        &self,
        session_id: &Uuid,
        host_ip: &str,
    ) -> Result<bool, DatabaseError> {
        let row = sqlx::query(
            "SELECT 1 FROM camera_screenshots WHERE scan_session_id = ? AND host_ip = ? LIMIT 1",
        )
        .bind(session_id.to_string())
        .bind(host_ip)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.is_some())
    }

    /// Checks if a camera screenshot exists for a given host and RTSP URL in a session
    pub async fn has_camera_screenshot_for_url(
        &self,
        session_id: &Uuid,
        host_ip: &str,
        rtsp_url: &str,
    ) -> Result<bool, DatabaseError> {
        let row = sqlx::query(
            "SELECT 1 FROM camera_screenshots WHERE scan_session_id = ? AND host_ip = ? AND rtsp_url = ? LIMIT 1",
        )
        .bind(session_id.to_string())
        .bind(host_ip)
        .bind(rtsp_url)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.is_some())
    }

    /// Retrieves all scan sessions, ordered by start time (most recent first)
    pub async fn get_scan_sessions(&self) -> Result<Vec<ScanSession>, DatabaseError> {
        let rows = sqlx::query("SELECT * FROM scan_sessions ORDER BY start_time DESC")
            .fetch_all(&self.pool)
            .await?;

        rows.into_iter()
            .map(|row| Self::row_to_scan_session(&row))
            .collect()
    }

    /// Retrieves all hosts for a given scan session
    pub async fn get_hosts_by_session(
        &self,
        session_id: &Uuid,
    ) -> Result<Vec<Host>, DatabaseError> {
        let rows = sqlx::query("SELECT * FROM hosts WHERE scan_session_id = ? ORDER BY ip_address")
            .bind(session_id.to_string())
            .fetch_all(&self.pool)
            .await?;

        rows.into_iter()
            .map(|row| Self::row_to_host(&row))
            .collect()
    }

    /// Retrieves all ports for a given host
    pub async fn get_ports_by_host(&self, host_id: &Uuid) -> Result<Vec<Port>, DatabaseError> {
        let rows = sqlx::query("SELECT * FROM ports WHERE host_id = ? ORDER BY port_number")
            .bind(host_id.to_string())
            .fetch_all(&self.pool)
            .await?;

        rows.into_iter()
            .map(|row| Self::row_to_port(&row))
            .collect()
    }

    /// Creates a new scan progress entry
    pub async fn create_scan_progress(
        &self,
        scan_session_id: &Uuid,
        chunk_range: &str,
        stage: &str,
    ) -> Result<Uuid, DatabaseError> {
        let id = Uuid::new_v4();
        let now = Utc::now().to_rfc3339();

        sqlx::query(
            "INSERT INTO scan_progress (id, scan_session_id, chunk_range, stage, status, started_at) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(id.to_string())
        .bind(scan_session_id.to_string())
        .bind(chunk_range)
        .bind(stage)
        .bind("pending")
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(id)
    }

    /// Updates the status of a scan progress entry
    pub async fn update_scan_progress_status(
        &self,
        id: &Uuid,
        status: &str,
        error_message: Option<&str>,
    ) -> Result<(), DatabaseError> {
        let now = Utc::now().to_rfc3339();

        sqlx::query(
            "UPDATE scan_progress SET status = ?, completed_at = ?, error_message = ? WHERE id = ?",
        )
        .bind(status)
        .bind(&now)
        .bind(error_message)
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Retrieves all scan progress entries for a given session
    pub async fn get_scan_progress_by_session(
        &self,
        scan_session_id: &Uuid,
    ) -> Result<Vec<ScanProgress>, DatabaseError> {
        let rows = sqlx::query(
            "SELECT * FROM scan_progress WHERE scan_session_id = ? ORDER BY chunk_range, stage",
        )
        .bind(scan_session_id.to_string())
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| Self::row_to_scan_progress(&row))
            .collect()
    }

    /// Retrieves completed chunk ranges for a given stage
    pub async fn get_completed_chunks_for_stage(
        &self,
        scan_session_id: &Uuid,
        stage: &str,
    ) -> Result<Vec<String>, DatabaseError> {
        let rows = sqlx::query(
            "SELECT chunk_range FROM scan_progress WHERE scan_session_id = ? AND stage = ? AND status = 'completed'",
        )
        .bind(scan_session_id.to_string())
        .bind(stage)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|row| row.get("chunk_range")).collect())
    }

    /// Retrieves ports by session ID and port number
    pub async fn get_ports_by_session_and_port(
        &self,
        session_id: &Uuid,
        port_number: i32,
    ) -> Result<Vec<Port>, DatabaseError> {
        let rows = sqlx::query(
            "SELECT p.* FROM ports p 
             JOIN hosts h ON p.host_id = h.id 
             WHERE h.scan_session_id = ? AND p.port_number = ?",
        )
        .bind(session_id.to_string())
        .bind(port_number)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| Self::row_to_port(&row))
            .collect()
    }

    /// Gets device catalog entry by IP address
    pub async fn get_device_catalog(
        &self,
        ip_address: &str,
    ) -> Result<Option<DeviceCatalog>, DatabaseError> {
        let row = sqlx::query("SELECT * FROM device_catalog WHERE ip_address = ?")
            .bind(ip_address)
            .fetch_optional(&self.pool)
            .await?;

        row.map(|r| Self::row_to_device_catalog(&r)).transpose()
    }

    /// Creates or updates device catalog entry
    pub async fn upsert_device_catalog(
        &self,
        catalog: &DeviceCatalog,
    ) -> Result<(), DatabaseError> {
        let now = Utc::now().to_rfc3339();
        
        // Check if entry exists
        let existing = self.get_device_catalog(&catalog.ip_address).await?;
        
        if existing.is_some() {
            // Update existing entry
            sqlx::query(
                r#"
                UPDATE device_catalog
                SET name = ?, description = ?, campus_name = ?, latitude = ?, longitude = ?, floor_number = ?, updated_at = ?
                WHERE ip_address = ?
                "#,
            )
            .bind(&catalog.name)
            .bind(&catalog.description)
            .bind(&catalog.campus_name)
            .bind(catalog.latitude)
            .bind(catalog.longitude)
            .bind(catalog.floor_number)
            .bind(&now)
            .bind(&catalog.ip_address)
            .execute(&self.pool)
            .await?;
        } else {
            // Insert new entry
            sqlx::query(
                r#"
                INSERT INTO device_catalog (ip_address, name, description, campus_name, latitude, longitude, floor_number, updated_at, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(&catalog.ip_address)
            .bind(&catalog.name)
            .bind(&catalog.description)
            .bind(&catalog.campus_name)
            .bind(catalog.latitude)
            .bind(catalog.longitude)
            .bind(catalog.floor_number)
            .bind(&now)
            .bind(&now)
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }

    /// Gets all device catalog entries
    pub async fn get_all_device_catalog(&self) -> Result<Vec<DeviceCatalog>, DatabaseError> {
        let rows = sqlx::query("SELECT * FROM device_catalog ORDER BY ip_address")
            .fetch_all(&self.pool)
            .await?;

        rows.into_iter()
            .map(|row| Self::row_to_device_catalog(&row))
            .collect()
    }

    /// Creates a host history snapshot
    pub async fn create_host_history(
        &self,
        host: &Host,
        scan_session_id: &Uuid,
        ports: &[Port],
    ) -> Result<(), DatabaseError> {
        // Serialize ports to JSON
        let ports_json = serde_json::to_string(ports).unwrap_or_else(|_| "[]".to_string());
        
        let id = Uuid::new_v4();
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO host_history (id, ip_address, scan_session_id, hostname, status, mac_address, vendor, os_family, os_gen, os_type, uptime, last_boot, ports_snapshot, snapshot_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(id.to_string())
        .bind(&host.ip_address)
        .bind(scan_session_id.to_string())
        .bind(&host.hostname)
        .bind(&host.status)
        .bind(&host.mac_address)
        .bind(&host.vendor)
        .bind(&host.os_family)
        .bind(&host.os_gen)
        .bind(&host.os_type)
        .bind(host.uptime)
        .bind(host.last_boot.map(|dt| dt.to_rfc3339()))
        .bind(&ports_json)
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Gets host history for an IP address, ordered by most recent first
    pub async fn get_host_history(
        &self,
        ip_address: &str,
    ) -> Result<Vec<HostHistory>, DatabaseError> {
        let rows = sqlx::query(
            "SELECT * FROM host_history WHERE ip_address = ? ORDER BY snapshot_at DESC",
        )
        .bind(ip_address)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| Self::row_to_host_history(&row))
            .collect()
    }

    /// Gets hosts by IP address across all sessions (for history tracking)
    pub async fn get_hosts_by_ip(
        &self,
        ip_address: &str,
    ) -> Result<Vec<Host>, DatabaseError> {
        let rows = sqlx::query("SELECT * FROM hosts WHERE ip_address = ? ORDER BY discovered_at DESC")
            .bind(ip_address)
            .fetch_all(&self.pool)
            .await?;

        rows.into_iter()
            .map(|row| Self::row_to_host(&row))
            .collect()
    }

    /// Gets subnet catalog entry by CIDR
    pub async fn get_subnet_catalog(
        &self,
        cidr: &str,
    ) -> Result<Option<SubnetCatalog>, DatabaseError> {
        let row = sqlx::query("SELECT * FROM subnet_catalog WHERE cidr = ?")
            .bind(cidr)
            .fetch_optional(&self.pool)
            .await?;

        row.map(|r| Self::row_to_subnet_catalog(&r)).transpose()
    }

    /// Gets all subnet catalog entries
    pub async fn get_all_subnet_catalog(&self) -> Result<Vec<SubnetCatalog>, DatabaseError> {
        let rows = sqlx::query("SELECT * FROM subnet_catalog ORDER BY cidr")
            .fetch_all(&self.pool)
            .await?;

        rows.into_iter()
            .map(|row| Self::row_to_subnet_catalog(&row))
            .collect()
    }

    /// Gets subnets by status
    pub async fn get_subnets_by_status(
        &self,
        status: &str,
    ) -> Result<Vec<SubnetCatalog>, DatabaseError> {
        let rows = sqlx::query("SELECT * FROM subnet_catalog WHERE status = ? ORDER BY cidr")
            .bind(status)
            .fetch_all(&self.pool)
            .await?;

        rows.into_iter()
            .map(|row| Self::row_to_subnet_catalog(&row))
            .collect()
    }

    /// Creates or updates a subnet catalog entry
    pub async fn upsert_subnet_catalog(
        &self,
        subnet: &SubnetCatalog,
    ) -> Result<(), DatabaseError> {
        // Check if entry exists
        let existing = self.get_subnet_catalog(&subnet.cidr).await?;

        if existing.is_some() {
            // Update existing entry
            sqlx::query(
                r#"
                UPDATE subnet_catalog
                SET name = ?, campus_name = ?, subnet_size = ?, total_ips = ?, active_ips = ?, 
                    utilization_percent = ?, status = ?, last_seen = ?, discovery_sessions = ?
                WHERE cidr = ?
                "#,
            )
            .bind(&subnet.name)
            .bind(&subnet.campus_name)
            .bind(subnet.subnet_size)
            .bind(subnet.total_ips)
            .bind(subnet.active_ips)
            .bind(subnet.utilization_percent)
            .bind(&subnet.status)
            .bind(subnet.last_seen.to_rfc3339())
            .bind(subnet.discovery_sessions)
            .bind(&subnet.cidr)
            .execute(&self.pool)
            .await?;
        } else {
            // Insert new entry
            sqlx::query(
                r#"
                INSERT INTO subnet_catalog (cidr, name, campus_name, subnet_size, total_ips, active_ips, 
                    utilization_percent, status, first_discovered, last_seen, discovery_sessions)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(&subnet.cidr)
            .bind(&subnet.name)
            .bind(&subnet.campus_name)
            .bind(subnet.subnet_size)
            .bind(subnet.total_ips)
            .bind(subnet.active_ips)
            .bind(subnet.utilization_percent)
            .bind(&subnet.status)
            .bind(subnet.first_discovered.to_rfc3339())
            .bind(subnet.last_seen.to_rfc3339())
            .bind(subnet.discovery_sessions)
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }

    /// Updates subnet metadata (name, campus) without changing utilization stats
    pub async fn update_subnet_metadata(
        &self,
        cidr: &str,
        name: Option<String>,
        campus_name: Option<String>,
    ) -> Result<(), DatabaseError> {
        let existing = self.get_subnet_catalog(cidr).await?;
        
        if existing.is_none() {
            return Err(DatabaseError::Sqlx(sqlx::Error::RowNotFound));
        }

        sqlx::query(
            "UPDATE subnet_catalog SET name = ?, campus_name = ? WHERE cidr = ?",
        )
        .bind(&name)
        .bind(&campus_name)
        .bind(cidr)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Changes a subnet's CIDR (effectively renaming/merging)
    pub async fn change_subnet_cidr(
        &self,
        old_cidr: &str,
        new_cidr: &str,
    ) -> Result<(), DatabaseError> {
        // Check if old subnet exists
        let old_subnet = self.get_subnet_catalog(old_cidr).await?;
        if old_subnet.is_none() {
            return Err(DatabaseError::Sqlx(sqlx::Error::RowNotFound));
        }

        // Check if new CIDR already exists
        let new_subnet = self.get_subnet_catalog(new_cidr).await?;
        
        if let Some(new_sub) = new_subnet {
            // Merge: delete old, update new with merged stats
            let old = old_subnet.unwrap();
            let mut merged = new_sub;
            
            // Merge discovery sessions count
            merged.discovery_sessions += old.discovery_sessions;
            
            // Update first_discovered to earliest
            if old.first_discovered < merged.first_discovered {
                merged.first_discovered = old.first_discovered;
            }
            
            // Update last_seen to most recent
            if old.last_seen > merged.last_seen {
                merged.last_seen = old.last_seen;
            }
            
            // Recalculate utilization (this might need manual adjustment)
            // For now, we'll keep the new subnet's stats but update counts
            
            self.upsert_subnet_catalog(&merged).await?;
            self.delete_subnet_catalog(old_cidr).await?;
        } else {
            // Simple rename: just update the CIDR
            sqlx::query("UPDATE subnet_catalog SET cidr = ? WHERE cidr = ?")
                .bind(new_cidr)
                .bind(old_cidr)
                .execute(&self.pool)
                .await?;
        }

        Ok(())
    }

    /// Deletes a subnet catalog entry
    pub async fn delete_subnet_catalog(&self, cidr: &str) -> Result<(), DatabaseError> {
        sqlx::query("DELETE FROM subnet_catalog WHERE cidr = ?")
            .bind(cidr)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Gets all unique IP addresses from all hosts (for subnet detection)
    pub async fn get_all_discovered_ips(&self) -> Result<Vec<String>, DatabaseError> {
        let rows = sqlx::query("SELECT DISTINCT ip_address FROM hosts ORDER BY ip_address")
            .fetch_all(&self.pool)
            .await?;

        Ok(rows.into_iter().map(|row| row.get("ip_address")).collect())
    }

    /// Parses a database row into a `ScanSession`
    fn row_to_scan_session(row: &sqlx::sqlite::SqliteRow) -> Result<ScanSession, DatabaseError> {
        let id_str: String = row.get("id");
        let start_time_str: String = row.get("start_time");
        let end_time_str: Option<String> = row.get("end_time");

        Ok(ScanSession {
            id: Uuid::parse_str(&id_str)?,
            target_range: row.get("target_range"),
            start_time: DateTime::parse_from_rfc3339(&start_time_str)?.with_timezone(&Utc),
            end_time: end_time_str
                .map(|s| DateTime::parse_from_rfc3339(&s).map(|dt| dt.with_timezone(&Utc)))
                .transpose()?,
            total_hosts: row.get("total_hosts"),
            hosts_up: row.get("hosts_up"),
            hosts_down: row.get("hosts_down"),
            config_json: row.get("config_json"),
        })
    }

    /// Parses a database row into a `Host`
    fn row_to_host(row: &sqlx::sqlite::SqliteRow) -> Result<Host, DatabaseError> {
        let id_str: String = row.get("id");
        let scan_session_id_str: String = row.get("scan_session_id");
        let discovered_at_str: String = row.get("discovered_at");
        let last_boot_str: Option<String> = row.get("last_boot");

        Ok(Host {
            id: Uuid::parse_str(&id_str)?,
            scan_session_id: Uuid::parse_str(&scan_session_id_str)?,
            ip_address: row.get("ip_address"),
            hostname: row.get("hostname"),
            status: row.get("status"),
            mac_address: row.get("mac_address"),
            vendor: row.get("vendor"),
            os_family: row.get("os_family"),
            os_gen: row.get("os_gen"),
            os_type: row.get("os_type"),
            uptime: row.get("uptime"),
            last_boot: last_boot_str
                .map(|s| DateTime::parse_from_rfc3339(&s).map(|dt| dt.with_timezone(&Utc)))
                .transpose()?,
            discovered_at: DateTime::parse_from_rfc3339(&discovered_at_str)?.with_timezone(&Utc),
        })
    }

    /// Parses a database row into a `Port`
    fn row_to_port(row: &sqlx::sqlite::SqliteRow) -> Result<Port, DatabaseError> {
        let id_str: String = row.get("id");
        let host_id_str: String = row.get("host_id");
        let discovered_at_str: String = row.get("discovered_at");

        Ok(Port {
            id: Uuid::parse_str(&id_str)?,
            host_id: Uuid::parse_str(&host_id_str)?,
            port_number: row.get("port_number"),
            protocol: row.get("protocol"),
            state: row.get("state"),
            service_name: row.get("service_name"),
            service_version: row.get("service_version"),
            service_product: row.get("service_product"),
            service_extrainfo: row.get("service_extrainfo"),
            service_fingerprint: row.get("service_fingerprint"),
            discovered_at: DateTime::parse_from_rfc3339(&discovered_at_str)?.with_timezone(&Utc),
        })
    }

    /// Parses a database row into a `CameraScreenshot`
    fn row_to_camera_screenshot(
        row: &sqlx::sqlite::SqliteRow,
    ) -> Result<CameraScreenshot, DatabaseError> {
        let id_str: String = row.get("id");
        let scan_session_id_str: String = row.get("scan_session_id");
        let captured_at_str: String = row.get("captured_at");

        Ok(CameraScreenshot {
            id: Uuid::parse_str(&id_str)?,
            scan_session_id: Uuid::parse_str(&scan_session_id_str)?,
            host_ip: row.get("host_ip"),
            rtsp_url: row.get("rtsp_url"),
            screenshot_path: row.get("screenshot_path"),
            captured_at: DateTime::parse_from_rfc3339(&captured_at_str)?.with_timezone(&Utc),
            error_message: row.get("error_message"),
            camera_index: row.try_get("camera_index").ok(),
            camera_type: row.try_get("camera_type").ok(),
        })
    }

    /// Parses a database row into a `ScanProgress`
    fn row_to_scan_progress(row: &sqlx::sqlite::SqliteRow) -> Result<ScanProgress, DatabaseError> {
        let id_str: String = row.get("id");
        let scan_session_id_str: String = row.get("scan_session_id");
        let started_at_str: Option<String> = row.get("started_at");
        let completed_at_str: Option<String> = row.get("completed_at");

        Ok(ScanProgress {
            id: Uuid::parse_str(&id_str)?,
            scan_session_id: Uuid::parse_str(&scan_session_id_str)?,
            chunk_range: row.get("chunk_range"),
            stage: row.get("stage"),
            status: row.get("status"),
            started_at: started_at_str
                .map(|s| DateTime::parse_from_rfc3339(&s).map(|dt| dt.with_timezone(&Utc)))
                .transpose()?,
            completed_at: completed_at_str
                .map(|s| DateTime::parse_from_rfc3339(&s).map(|dt| dt.with_timezone(&Utc)))
                .transpose()?,
            error_message: row.get("error_message"),
        })
    }

    /// Parses a database row into a `DeviceCatalog`
    fn row_to_device_catalog(row: &sqlx::sqlite::SqliteRow) -> Result<DeviceCatalog, DatabaseError> {
        let updated_at_str: String = row.get("updated_at");
        let created_at_str: String = row.get("created_at");

        Ok(DeviceCatalog {
            ip_address: row.get("ip_address"),
            name: row.get("name"),
            description: row.get("description"),
            campus_name: row.get("campus_name"),
            latitude: row.try_get("latitude").ok(),
            longitude: row.try_get("longitude").ok(),
            floor_number: row.try_get("floor_number").ok(),
            updated_at: DateTime::parse_from_rfc3339(&updated_at_str)?.with_timezone(&Utc),
            created_at: DateTime::parse_from_rfc3339(&created_at_str)?.with_timezone(&Utc),
        })
    }

    /// Parses a database row into a `HostHistory`
    fn row_to_host_history(row: &sqlx::sqlite::SqliteRow) -> Result<HostHistory, DatabaseError> {
        let id_str: String = row.get("id");
        let scan_session_id_str: String = row.get("scan_session_id");
        let snapshot_at_str: String = row.get("snapshot_at");
        let last_boot_str: Option<String> = row.get("last_boot");

        Ok(HostHistory {
            id: Uuid::parse_str(&id_str)?,
            ip_address: row.get("ip_address"),
            scan_session_id: Uuid::parse_str(&scan_session_id_str)?,
            hostname: row.get("hostname"),
            status: row.get("status"),
            mac_address: row.get("mac_address"),
            vendor: row.get("vendor"),
            os_family: row.get("os_family"),
            os_gen: row.get("os_gen"),
            os_type: row.get("os_type"),
            uptime: row.get("uptime"),
            last_boot: last_boot_str
                .map(|s| DateTime::parse_from_rfc3339(&s).map(|dt| dt.with_timezone(&Utc)))
                .transpose()?,
            ports_snapshot: row.get("ports_snapshot"),
            snapshot_at: DateTime::parse_from_rfc3339(&snapshot_at_str)?.with_timezone(&Utc),
        })
    }

    /// Parses a database row into a `SubnetCatalog`
    fn row_to_subnet_catalog(row: &sqlx::sqlite::SqliteRow) -> Result<SubnetCatalog, DatabaseError> {
        let first_discovered_str: String = row.get("first_discovered");
        let last_seen_str: String = row.get("last_seen");

        Ok(SubnetCatalog {
            cidr: row.get("cidr"),
            name: row.get("name"),
            campus_name: row.get("campus_name"),
            subnet_size: row.get("subnet_size"),
            total_ips: row.get("total_ips"),
            active_ips: row.get("active_ips"),
            utilization_percent: row.get("utilization_percent"),
            status: row.get("status"),
            first_discovered: DateTime::parse_from_rfc3339(&first_discovered_str)?.with_timezone(&Utc),
            last_seen: DateTime::parse_from_rfc3339(&last_seen_str)?.with_timezone(&Utc),
            discovery_sessions: row.get("discovery_sessions"),
        })
    }
}
