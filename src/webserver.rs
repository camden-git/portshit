use anyhow::{Context, Result};
use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::get,
    Router,
};
use crate::database::{Database, DeviceCatalog, CameraScreenshot};
use serde::Serialize;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{info, warn};
use uuid::Uuid;

/// App state containing database and API key
#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Database>,
    pub api_key: String,
}

/// Response type for device catalog list
#[derive(Debug, Serialize)]
pub struct DeviceListResponse {
    pub devices: Vec<DeviceCatalog>,
}

/// Response type for camera screenshots
#[derive(Debug, Serialize)]
pub struct ScreenshotListResponse {
    pub screenshots: Vec<CameraScreenshot>,
}

/// Response type for device cameras (RTSP URLs)
#[derive(Debug, Serialize)]
pub struct CameraListResponse {
    pub cameras: Vec<CameraInfo>,
}

/// Camera information with RTSP URL and metadata
#[derive(Debug, Serialize)]
pub struct CameraInfo {
    /// RTSP URL with camera parameter (e.g., rtsp://user:pass@ip:554/axis-media/media.amp?camera=1)
    pub rtsp_url: String,
    /// Camera index (1, 2, 3, etc. for individual cameras, or None for default/single camera)
    pub camera_index: Option<i32>,
    /// Camera type: "individual", "grid", "default", or null
    pub camera_type: Option<String>,
    /// Most recent screenshot ID for this camera (if available)
    pub latest_screenshot_id: Option<String>,
    /// Timestamp of most recent screenshot capture (if available)
    pub latest_captured_at: Option<String>,
}

/// Error response
#[derive(Debug, Serialize)]
struct ErrorResponse {
    pub error: String,
}

/// Creates and runs the webserver
pub async fn run_server(
    database_path: String,
    api_key: String,
    bind_address: String,
) -> Result<()> {
    info!("Starting webserver on {}", bind_address);
    info!("API key: {} (use this in Authorization: Bearer <key> header)", api_key);

    let db = Arc::new(
        Database::new(&database_path)
            .await
            .context("Failed to create database connection")?,
    );

    let state = AppState {
        db,
        api_key: api_key.clone(),
    };

    // API routes that require authentication
    let api_routes = Router::new()
        .route("/api/devices", get(list_devices))
        .route("/api/devices/:ip/cameras", get(get_device_cameras))
        .route("/api/devices/:ip/screenshots", get(get_device_screenshots))
        .route("/api/screenshots/:id/image", get(get_screenshot_image))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .with_state(state.clone());

    // Public routes (no auth)
    let public_routes = Router::new().route("/health", get(health_check));

    // Combine routes
    let app = Router::new()
        .merge(public_routes)
        .merge(api_routes);

    let listener = TcpListener::bind(&bind_address)
        .await
        .context(format!("Failed to bind to {}", bind_address))?;

    info!("Webserver listening on http://{}", bind_address);
    info!("API endpoints:");
    info!("  GET /api/devices - List all device catalog entries");
    info!("  GET /api/devices/:ip/cameras - Get all cameras (RTSP URLs) for a device");
    info!("  GET /api/devices/:ip/screenshots - Get camera screenshots for a device");
    info!("  GET /api/screenshots/:id/image - Get screenshot image file");

    axum::serve(listener, app)
        .await
        .context("Webserver error")?;

    Ok(())
}

/// Health check endpoint (no auth required)
async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

/// Authentication middleware - checks for Bearer token in Authorization header
async fn auth_middleware(
    State(state): State<AppState>,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    // Extract Authorization header
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    // Check for Bearer token
    if !auth_header.starts_with("Bearer ") {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Missing or invalid Authorization header. Use: Authorization: Bearer <api_key>".to_string(),
            }),
        )
            .into_response();
    }

    let token = &auth_header[7..]; // Skip "Bearer "

    if token != state.api_key {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid API key".to_string(),
            }),
        )
            .into_response();
    }

    next.run(request).await
}

/// List all device catalog entries
async fn list_devices(State(state): State<AppState>) -> impl IntoResponse {
    match state.db.get_all_device_catalog().await {
        Ok(devices) => {
            (StatusCode::OK, Json(DeviceListResponse { devices })).into_response()
        }
        Err(e) => AppError::Database(e.to_string()).into_response(),
    }
}

/// Get all cameras (RTSP URLs) for a specific device IP
async fn get_device_cameras(
    State(state): State<AppState>,
    Path(ip_address): Path<String>,
) -> impl IntoResponse {
    match state.db.get_cameras_by_host_ip(&ip_address).await {
        Ok(screenshots) => {
            // Convert screenshots to camera info, extracting unique cameras
            let cameras: Vec<CameraInfo> = screenshots
                .into_iter()
                .map(|s| CameraInfo {
                    rtsp_url: s.rtsp_url,
                    camera_index: s.camera_index,
                    camera_type: s.camera_type,
                    latest_screenshot_id: Some(s.id.to_string()),
                    latest_captured_at: Some(s.captured_at.to_rfc3339()),
                })
                .collect();

            (StatusCode::OK, Json(CameraListResponse { cameras })).into_response()
        }
        Err(e) => AppError::Database(e.to_string()).into_response(),
    }
}

/// Get camera screenshots for a specific device IP
async fn get_device_screenshots(
    State(state): State<AppState>,
    Path(ip_address): Path<String>,
) -> impl IntoResponse {
    match state.db.get_camera_screenshots_by_host_ip(&ip_address).await {
        Ok(screenshots) => {
            (StatusCode::OK, Json(ScreenshotListResponse { screenshots })).into_response()
        }
        Err(e) => AppError::Database(e.to_string()).into_response(),
    }
}

/// Get screenshot image file by screenshot ID
async fn get_screenshot_image(
    State(state): State<AppState>,
    Path(screenshot_id): Path<String>,
) -> impl IntoResponse {
    // Parse UUID
    let uuid = match Uuid::parse_str(&screenshot_id) {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid screenshot ID format".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Get screenshot metadata from database
    let screenshot = match state.db.get_camera_screenshot_by_id(&uuid).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Screenshot not found".to_string(),
                }),
            )
                .into_response();
        }
        Err(e) => {
            return AppError::Database(e.to_string()).into_response();
        }
    };

    // Check if file exists and read it
    match tokio::fs::read(&screenshot.screenshot_path).await {
        Ok(image_data) => {
            // Determine content type based on file extension
            let content_type = if screenshot.screenshot_path.ends_with(".jpg")
                || screenshot.screenshot_path.ends_with(".jpeg")
            {
                "image/jpeg"
            } else if screenshot.screenshot_path.ends_with(".png") {
                "image/png"
            } else {
                "image/jpeg" // Default to JPEG
            };

            let mut response = Response::new(axum::body::Body::from(image_data));
            *response.status_mut() = StatusCode::OK;
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_str(content_type).unwrap(),
            );
            response.headers_mut().insert(
                header::CONTENT_DISPOSITION,
                header::HeaderValue::from_str(&format!(
                    "inline; filename=\"{}\"",
                    std::path::Path::new(&screenshot.screenshot_path)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("screenshot.jpg")
                ))
                .unwrap(),
            );
            response.into_response()
        }
        Err(e) => {
            warn!(
                "Failed to read screenshot file {}: {}",
                screenshot.screenshot_path, e
            );
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("Screenshot file not found: {}", e),
                }),
            )
                .into_response()
        }
    }
}


/// Application error type
#[derive(Debug)]
pub enum AppError {
    Database(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::Database(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        let body = Json(ErrorResponse {
            error: error_message,
        });

        (status, body).into_response()
    }
}

