use anyhow::{Context, Result};
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct NetworkRange {
    pub start_ip: IpAddr,
    pub end_ip: IpAddr,
    pub cidr: u8,
}

impl NetworkRange {
    pub fn from_cidr(cidr: &str) -> Result<Self> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("Invalid CIDR format: {}", cidr));
        }

        let ip = IpAddr::from_str(parts[0])
            .context("Invalid IP address")?;
        let prefix_len: u8 = parts[1].parse()
            .context("Invalid prefix length")?;

        let (start_ip, end_ip) = Self::calculate_range(ip, prefix_len)?;

        Ok(Self {
            start_ip,
            end_ip,
            cidr: prefix_len,
        })
    }

    pub fn from_range(range: &str) -> Result<Self> {
        if range.contains('/') {
            return Self::from_cidr(range);
        }

        if range.contains('-') {
            let parts: Vec<&str> = range.split('-').collect();
            if parts.len() != 2 {
                return Err(anyhow::anyhow!("Invalid range format: {}", range));
            }

            let start_ip = IpAddr::from_str(parts[0].trim())
                .context("Invalid start IP address")?;
            let end_ip = IpAddr::from_str(parts[1].trim())
                .context("Invalid end IP address")?;

            // calculate CIDR from range
            let cidr = Self::calculate_cidr_from_range(start_ip, end_ip)?;

            Ok(Self {
                start_ip,
                end_ip,
                cidr,
            })
        } else {
            // single IP
            let ip = IpAddr::from_str(range)
                .context("Invalid IP address")?;
            Ok(Self {
                start_ip: ip,
                end_ip: ip,
                cidr: 32,
            })
        }
    }

    fn calculate_range(ip: IpAddr, prefix_len: u8) -> Result<(IpAddr, IpAddr)> {
        match ip {
            IpAddr::V4(ipv4) => {
                let ip_u32 = u32::from(ipv4);
                let mask = if prefix_len == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix_len)
                };
                let network = ip_u32 & mask;
                let broadcast = network | (!mask);
                
                let start_ip = IpAddr::V4(std::net::Ipv4Addr::from(network));
                let end_ip = IpAddr::V4(std::net::Ipv4Addr::from(broadcast));
                
                Ok((start_ip, end_ip))
            }
            IpAddr::V6(_) => {
                Err(anyhow::anyhow!("IPv6 not supported yet"))
            }
        }
    }

    fn calculate_cidr_from_range(start_ip: IpAddr, end_ip: IpAddr) -> Result<u8> {
        match (start_ip, end_ip) {
            (IpAddr::V4(start), IpAddr::V4(end)) => {
                let start_u32 = u32::from(start);
                let end_u32 = u32::from(end);
                let _range = end_u32 - start_u32 + 1;
                
                // find the smallest CIDR that contains this range
                for cidr in 0..=32 {
                    let mask = if cidr == 0 { 0 } else { u32::MAX << (32 - cidr) };
                    let network = start_u32 & mask;
                    let broadcast = network | (!mask);
                    
                    if start_u32 >= network && end_u32 <= broadcast {
                        return Ok(cidr);
                    }
                }
                
                Ok(32) // default to /32 if we can't determine
            }
            _ => Err(anyhow::anyhow!("IPv6 not supported yet, please see https://ipv6excuses.com/")),
        }
    }

    pub fn split_into_chunks(&self, chunk_size: u8) -> Result<Vec<NetworkRange>> {
        // if chunk size is smaller than or equal to the original network, return the original
        if chunk_size <= self.cidr {
            return Ok(vec![self.clone()]);
        }

        let mut chunks = Vec::new();
        
        match self.start_ip {
            IpAddr::V4(start_ipv4) => {
                let start_u32 = u32::from(start_ipv4);
                let end_u32 = u32::from(match self.end_ip {
                    IpAddr::V4(end_ipv4) => end_ipv4,
                    _ => return Err(anyhow::anyhow!("Mixed IPv4/IPv6 not supported")),
                });

                // calculate the chunk size in terms of IP addresses
                let chunk_size_u32 = 1u32 << (32 - chunk_size);
                
                // start from the network boundary
                let network_mask = u32::MAX << (32 - self.cidr);
                let network_start = start_u32 & network_mask;
                
                let mut current = network_start;
                while current <= end_u32 {
                    let chunk_start = current;
                    let chunk_end = (current + chunk_size_u32 - 1).min(end_u32);
                    
                    chunks.push(NetworkRange {
                        start_ip: IpAddr::V4(std::net::Ipv4Addr::from(chunk_start)),
                        end_ip: IpAddr::V4(std::net::Ipv4Addr::from(chunk_end)),
                        cidr: chunk_size,
                    });
                    
                    // move to the next chunk
                    current += chunk_size_u32;
                }
            }
            IpAddr::V6(_) => {
                return Err(anyhow::anyhow!("IPv6 not supported yet"));
            }
        }

        Ok(chunks)
    }

    pub fn to_cidr_string(&self) -> String {
        format!("{}/{}", self.start_ip, self.cidr)
    }

    pub fn to_range_string(&self) -> String {
        if self.start_ip == self.end_ip {
            self.start_ip.to_string()
        } else {
            format!("{}-{}", self.start_ip, self.end_ip)
        }
    }

    pub fn get_host_count(&self) -> u64 {
        match (self.start_ip, self.end_ip) {
            (IpAddr::V4(start), IpAddr::V4(end)) => {
                let start_u32 = u32::from(start);
                let end_u32 = u32::from(end);
                (end_u32 - start_u32 + 1) as u64
            }
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cidr_parsing() {
        let range = NetworkRange::from_cidr("192.168.1.0/24").unwrap();
        assert_eq!(range.cidr, 24);
        assert_eq!(range.get_host_count(), 256);
    }

    #[test]
    fn test_chunking() {
        let range = NetworkRange::from_cidr("192.168.0.0/16").unwrap();
        let chunks = range.split_into_chunks(24).unwrap();
        assert_eq!(chunks.len(), 256); // 256 /24 networks in a /16
        
        assert_eq!(chunks[0].start_ip.to_string(), "192.168.0.0");
        assert_eq!(chunks[0].end_ip.to_string(), "192.168.0.255");
        assert_eq!(chunks[0].cidr, 24);
        
        assert_eq!(chunks[255].start_ip.to_string(), "192.168.255.0");
        assert_eq!(chunks[255].end_ip.to_string(), "192.168.255.255");
        assert_eq!(chunks[255].cidr, 24);
    }
}
