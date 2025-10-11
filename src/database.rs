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
    pub status: String, // up, down, filtered
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
    pub protocol: String, // tcp, udp
    pub state: String,    // open, closed, filtered, unfiltered, open|filtered, closed|filtered
    pub service_name: Option<String>,
    pub service_version: Option<String>,
    pub service_product: Option<String>,
    pub service_extrainfo: Option<String>,
    pub service_fingerprint: Option<String>,
    pub discovered_at: DateTime<Utc>,
}

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
    pub error_message: Option<String>, // None for successful captures, Some(error) for failures
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub id: Uuid,
    pub scan_session_id: Uuid,
    pub chunk_range: String,
    pub stage: String, // "discovery", "service", "camera"
    pub status: String, // "pending", "in_progress", "completed", "failed"
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
}

#[derive(Clone)]
pub struct Database {
    pool: SqlitePool,
}

impl Database {
    pub async fn new(database_path: &str) -> Result<Self, sqlx::Error> {
        // create directory if it doesn't exist
        if let Some(parent) = std::path::Path::new(database_path).parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                sqlx::Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e))
            })?;
        }
        
        // create the database file if it doesn't exist
        if !std::path::Path::new(database_path).exists() {
            std::fs::File::create(database_path).map_err(|e| {
                sqlx::Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e))
            })?;
        }
        
        let pool = SqlitePool::connect(&format!("sqlite://{}", database_path)).await?;
        let db = Self { pool };
        db.create_tables().await?;
        Ok(db)
    }

    async fn create_tables(&self) -> Result<(), sqlx::Error> {
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
                FOREIGN KEY (scan_session_id) REFERENCES scan_sessions (id)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

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

        Ok(())
    }

    pub async fn create_scan_session(&self, session: &ScanSession) -> Result<(), sqlx::Error> {
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

    pub async fn update_scan_session(&self, session: &ScanSession) -> Result<(), sqlx::Error> {
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

    pub async fn insert_host(&self, host: &Host) -> Result<(), sqlx::Error> {
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

    pub async fn insert_port(&self, port: &Port) -> Result<(), sqlx::Error> {
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

    pub async fn insert_script_result(&self, script_result: &ScriptResult) -> Result<(), sqlx::Error> {
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

    pub async fn insert_camera_screenshot(&self, screenshot: &CameraScreenshot) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO camera_screenshots (id, scan_session_id, host_ip, rtsp_url, screenshot_path, captured_at, error_message)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(screenshot.id.to_string())
        .bind(screenshot.scan_session_id.to_string())
        .bind(&screenshot.host_ip)
        .bind(&screenshot.rtsp_url)
        .bind(&screenshot.screenshot_path)
        .bind(screenshot.captured_at.to_rfc3339())
        .bind(&screenshot.error_message)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_camera_screenshots_by_session(&self, session_id: &Uuid) -> Result<Vec<CameraScreenshot>, sqlx::Error> {
        let rows = sqlx::query("SELECT * FROM camera_screenshots WHERE scan_session_id = ? ORDER BY captured_at DESC")
            .bind(session_id.to_string())
            .fetch_all(&self.pool)
            .await?;

        let mut screenshots = Vec::new();
        for row in rows {
            let screenshot = CameraScreenshot {
                id: Uuid::parse_str(row.get("id")).unwrap(),
                scan_session_id: Uuid::parse_str(row.get("scan_session_id")).unwrap(),
                host_ip: row.get("host_ip"),
                rtsp_url: row.get("rtsp_url"),
                screenshot_path: row.get("screenshot_path"),
                captured_at: DateTime::parse_from_rfc3339(row.get("captured_at"))
                    .unwrap()
                    .with_timezone(&Utc),
                error_message: row.get("error_message"),
            };
            screenshots.push(screenshot);
        }

        Ok(screenshots)
    }

    pub async fn get_scan_sessions(&self) -> Result<Vec<ScanSession>, sqlx::Error> {
        let rows = sqlx::query("SELECT * FROM scan_sessions ORDER BY start_time DESC")
            .fetch_all(&self.pool)
            .await?;

        let mut sessions = Vec::new();
        for row in rows {
            let session = ScanSession {
                id: Uuid::parse_str(row.get("id")).unwrap(),
                target_range: row.get("target_range"),
                start_time: DateTime::parse_from_rfc3339(row.get("start_time"))
                    .unwrap()
                    .with_timezone(&Utc),
                end_time: row.get::<Option<String>, _>("end_time")
                    .map(|s| DateTime::parse_from_rfc3339(&s).unwrap().with_timezone(&Utc)),
                total_hosts: row.get("total_hosts"),
                hosts_up: row.get("hosts_up"),
                hosts_down: row.get("hosts_down"),
                config_json: row.get("config_json"),
            };
            sessions.push(session);
        }

        Ok(sessions)
    }

    pub async fn get_hosts_by_session(&self, session_id: &Uuid) -> Result<Vec<Host>, sqlx::Error> {
        let rows = sqlx::query("SELECT * FROM hosts WHERE scan_session_id = ? ORDER BY ip_address")
            .bind(session_id.to_string())
            .fetch_all(&self.pool)
            .await?;

        let mut hosts = Vec::new();
        for row in rows {
            let host = Host {
                id: Uuid::parse_str(row.get("id")).unwrap(),
                scan_session_id: Uuid::parse_str(row.get("scan_session_id")).unwrap(),
                ip_address: row.get("ip_address"),
                hostname: row.get("hostname"),
                status: row.get("status"),
                mac_address: row.get("mac_address"),
                vendor: row.get("vendor"),
                os_family: row.get("os_family"),
                os_gen: row.get("os_gen"),
                os_type: row.get("os_type"),
                uptime: row.get("uptime"),
                last_boot: row.get::<Option<String>, _>("last_boot")
                    .map(|s| DateTime::parse_from_rfc3339(&s).unwrap().with_timezone(&Utc)),
                discovered_at: DateTime::parse_from_rfc3339(row.get("discovered_at"))
                    .unwrap()
                    .with_timezone(&Utc),
            };
            hosts.push(host);
        }

        Ok(hosts)
    }

    pub async fn get_ports_by_host(&self, host_id: &Uuid) -> Result<Vec<Port>, sqlx::Error> {
        let rows = sqlx::query("SELECT * FROM ports WHERE host_id = ? ORDER BY port_number")
            .bind(host_id.to_string())
            .fetch_all(&self.pool)
            .await?;

        let mut ports = Vec::new();
        for row in rows {
            let port = Port {
                id: Uuid::parse_str(row.get("id")).unwrap(),
                host_id: Uuid::parse_str(row.get("host_id")).unwrap(),
                port_number: row.get("port_number"),
                protocol: row.get("protocol"),
                state: row.get("state"),
                service_name: row.get("service_name"),
                service_version: row.get("service_version"),
                service_product: row.get("service_product"),
                service_extrainfo: row.get("service_extrainfo"),
                service_fingerprint: row.get("service_fingerprint"),
                discovered_at: DateTime::parse_from_rfc3339(row.get("discovered_at"))
                    .unwrap()
                    .with_timezone(&Utc),
            };
            ports.push(port);
        }

        Ok(ports)
    }

    // scan progress management methods
    pub async fn create_scan_progress(
        &self,
        scan_session_id: &Uuid,
        chunk_range: &str,
        stage: &str,
    ) -> Result<Uuid, sqlx::Error> {
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

    pub async fn update_scan_progress_status(
        &self,
        id: &Uuid,
        status: &str,
        error_message: Option<&str>,
    ) -> Result<(), sqlx::Error> {
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

    pub async fn get_scan_progress_by_session(
        &self,
        scan_session_id: &Uuid,
    ) -> Result<Vec<ScanProgress>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT * FROM scan_progress WHERE scan_session_id = ? ORDER BY chunk_range, stage",
        )
        .bind(scan_session_id.to_string())
        .fetch_all(&self.pool)
        .await?;

        let mut progress = Vec::new();
        for row in rows {
            progress.push(ScanProgress {
                id: Uuid::parse_str(row.get("id")).unwrap(),
                scan_session_id: Uuid::parse_str(row.get("scan_session_id")).unwrap(),
                chunk_range: row.get("chunk_range"),
                stage: row.get("stage"),
                status: row.get("status"),
                started_at: row.get::<Option<String>, _>("started_at")
                    .map(|s| DateTime::parse_from_rfc3339(&s).unwrap().with_timezone(&Utc)),
                completed_at: row.get::<Option<String>, _>("completed_at")
                    .map(|s| DateTime::parse_from_rfc3339(&s).unwrap().with_timezone(&Utc)),
                error_message: row.get("error_message"),
            });
        }

        Ok(progress)
    }

    pub async fn get_completed_chunks_for_stage(
        &self,
        scan_session_id: &Uuid,
        stage: &str,
    ) -> Result<Vec<String>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT chunk_range FROM scan_progress WHERE scan_session_id = ? AND stage = ? AND status = 'completed'",
        )
        .bind(scan_session_id.to_string())
        .bind(stage)
        .fetch_all(&self.pool)
        .await?;

        let chunks: Vec<String> = rows.into_iter().map(|row| row.get("chunk_range")).collect();
        Ok(chunks)
    }

    pub async fn get_ports_by_session_and_port(
        &self,
        session_id: &Uuid,
        port_number: i32,
    ) -> Result<Vec<Port>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT p.* FROM ports p 
             JOIN hosts h ON p.host_id = h.id 
             WHERE h.scan_session_id = ? AND p.port_number = ?"
        )
        .bind(session_id.to_string())
        .bind(port_number)
        .fetch_all(&self.pool)
        .await?;

        let mut ports = Vec::new();
        for row in rows {
            let port = Port {
                id: Uuid::parse_str(row.get("id")).unwrap(),
                host_id: Uuid::parse_str(row.get("host_id")).unwrap(),
                port_number: row.get("port_number"),
                protocol: row.get("protocol"),
                state: row.get("state"),
                service_name: row.get("service_name"),
                service_version: row.get("service_version"),
                service_product: row.get("service_product"),
                service_extrainfo: row.get("service_extrainfo"),
                service_fingerprint: row.get("service_fingerprint"),
                discovered_at: DateTime::parse_from_rfc3339(row.get("discovered_at"))
                    .unwrap()
                    .with_timezone(&Utc),
            };
            ports.push(port);
        }

        Ok(ports)
    }
}
