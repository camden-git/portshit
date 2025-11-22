use crate::database::{Database, SubnetCatalog};
use anyhow::{Context, Result};
use chrono::Utc;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use tracing::{debug, info, warn};

/// common subnet sizes to try during detection
const COMMON_SUBNET_SIZES: &[i32] = &[24, 22, 20, 16];

/// detects subnets from discovered IP addresses
pub struct SubnetDetector;

impl SubnetDetector {
    /// detects subnets from all discovered IP addresses in the database
    pub async fn detect_subnets(db: &Database) -> Result<Vec<SubnetCatalog>> {
        info!("Starting subnet detection from discovered IPs");

        let ips = db.get_all_discovered_ips().await?;

        if ips.is_empty() {
            info!("No IPs found skipping subnet detection");
            return Ok(vec![]);
        }

        info!("Processing {} unique IP addresses for subnet detection", ips.len());

        let ipv4_addrs: Vec<Ipv4Addr> = ips
            .iter()
            .filter_map(|ip_str| {
                match ip_str.parse::<IpAddr>() {
                    Ok(IpAddr::V4(ip)) => Some(ip),
                    Err(e) => {
                        warn!("Failed to parse IP {}: {}", ip_str, e);
                        None
                    }
                    _ => None,
                }
            })
            .collect();

        if ipv4_addrs.is_empty() {
            info!("No IPs found, skipping subnet detection");
            return Ok(vec![]);
        }

        info!("Found {} IP addresses", ipv4_addrs.len());

        let detected_subnets = Self::analyze_ips_for_subnets(&ipv4_addrs)?;

        info!("Found {} subnets", detected_subnets.len());

        Ok(detected_subnets)
    }
    
    /// analyzes IP addresses and returns detected subnets
    fn analyze_ips_for_subnets(ips: &[Ipv4Addr]) -> Result<Vec<SubnetCatalog>> {
        let mut subnet_map: HashMap<String, HashSet<Ipv4Addr>> = HashMap::new();
        let now = Utc::now();

        for &ip in ips {
            for &subnet_size in COMMON_SUBNET_SIZES {
                let cidr = Self::ip_to_cidr(ip, subnet_size)?;
                
                subnet_map
                    .entry(cidr)
                    .or_insert_with(HashSet::new)
                    .insert(ip);
            }
        }

        let mut subnets = Vec::new();

        for (cidr, ip_set) in subnet_map {
            let active_ips = ip_set.len() as i64;
            
            let subnet_size = Self::parse_subnet_size(&cidr)?;
            let total_ips = 2u64.pow(32 - subnet_size as u32) as i64;
            
            // only create subnet if it has active IPs
            if active_ips > 0 {
                let utilization_percent = (active_ips as f64 / total_ips as f64) * 100.0;
                
                let status = if active_ips > 0 {
                    "in_use"
                } else {
                    "unused"
                };

                let subnet = SubnetCatalog {
                    cidr,
                    name: None,
                    campus_name: None,
                    subnet_size,
                    total_ips,
                    active_ips,
                    utilization_percent,
                    status: status.to_string(),
                    first_discovered: now,
                    last_seen: now,
                    discovery_sessions: 1,
                };

                subnets.push(subnet);
            }
        }

        // remove redundant subnets
        let filtered_subnets = Self::filter_redundant_subnets(subnets)?;

        Ok(filtered_subnets)
    }

    /// converts an IP address to CIDR notation for a given subnet size
    fn ip_to_cidr(ip: Ipv4Addr, subnet_size: i32) -> Result<String> {
        let ip_u32 = u32::from(ip);
        let mask = !((1u32 << (32 - subnet_size)) - 1);
        let network_u32 = ip_u32 & mask;
        let network_ip = Ipv4Addr::from(network_u32);

        Ok(format!("{}/{}", network_ip, subnet_size))
    }

    /// parses subnet size from CIDR notation
    fn parse_subnet_size(cidr: &str) -> Result<i32> {
        cidr
            .split('/')
            .nth(1)
            .and_then(|s| s.parse::<i32>().ok())
            .context(format!("Failed to parse subnet size from CIDR: {}", cidr))
    }

    /// filters out redundant subnets
    /// prefers smaller, more specific subnets over larger ones
    fn filter_redundant_subnets(mut subnets: Vec<SubnetCatalog>) -> Result<Vec<SubnetCatalog>> {
        // sort by subnet size (smallest first, so we prefer more specific subnets)
        subnets.sort_by(|a, b| a.subnet_size.cmp(&b.subnet_size));

        let mut filtered = Vec::new();
        let mut processed_networks: HashSet<String> = HashSet::new();

        // process subnets from smallest to largest (most specific first)
        for subnet in subnets {
            // check if this subnet's network is already covered by a more specific subnet
            // for example, if 10.1.2.0/24 exists, don't add 10.1.0.0/16
            // check if any processed subnet contains this one
            let is_redundant = processed_networks.iter().any(|existing_cidr| {
                Self::contains_subnet(existing_cidr, &subnet.cidr).unwrap_or(false)
            });
            
            if !is_redundant {
                processed_networks.insert(subnet.cidr.clone());
                filtered.push(subnet);
            } else {
                debug!(
                    "Filtering out redundant subnet {} (already covered by more specific subnet)",
                    subnet.cidr
                );
            }
        }

        Ok(filtered)
    }

    /// gets the network base IP from CIDR
    fn get_network_base(cidr: &str) -> Result<String> {
        cidr.split('/')
            .next()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("Invalid CIDR format: {}", cidr))
    }

    /// checks if parent_cidr contains child_cidr
    fn contains_subnet(parent_cidr: &str, child_cidr: &str) -> Result<bool> {
        let parent_parts: Vec<&str> = parent_cidr.split('/').collect();
        let child_parts: Vec<&str> = child_cidr.split('/').collect();
        
        if parent_parts.len() != 2 || child_parts.len() != 2 {
            return Ok(false);
        }

        let parent_ip = parent_parts[0].parse::<Ipv4Addr>()?;
        let parent_size: u32 = parent_parts[1].parse()?;
        let child_ip = child_parts[0].parse::<Ipv4Addr>()?;
        let child_size: u32 = child_parts[1].parse()?;

        // parent must be larger (smaller mask size means larger network)
        if parent_size >= child_size {
            return Ok(false);
        }

        // check if child network is within parent network
        let parent_mask = !((1u32 << (32 - parent_size)) - 1);
        let parent_network = u32::from(parent_ip) & parent_mask;
        let child_network = u32::from(child_ip) & parent_mask;

        Ok(parent_network == child_network)
    }


    /// updates or creates subnet catalog entries in the database
    pub async fn update_subnet_catalog(
        db: &Database,
        detected_subnets: &[SubnetCatalog],
    ) -> Result<()> {
        info!("Updating subnet catalog with {} detected subnets", detected_subnets.len());

        for subnet in detected_subnets {
            // get existing subnet if it exists
            let existing = db.get_subnet_catalog(&subnet.cidr).await?;

            let updated_subnet = if let Some(mut existing_sub) = existing {
                // update existing subnet
                existing_sub.active_ips = subnet.active_ips;
                existing_sub.utilization_percent = subnet.utilization_percent;
                existing_sub.last_seen = Utc::now();
                existing_sub.discovery_sessions += 1;

                // update status based on active IPs
                existing_sub.status = if existing_sub.active_ips > 0 {
                    "in_use".to_string()
                } else {
                    "unused".to_string()
                };

                existing_sub
            } else {
                subnet.clone()
            };

            db.upsert_subnet_catalog(&updated_subnet).await?;
        }

        info!("Subnet catalog update completed");
        Ok(())
    }
}

