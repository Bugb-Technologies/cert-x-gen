//! Utility functions and helpers

use crate::error::{Error, Result};
use std::net::IpAddr;
use std::str::FromStr;

/// Parse target specification into host and port
pub fn parse_target(target: &str) -> Result<(String, Option<u16>)> {
    if target.contains("://") {
        // URL format
        let url = url::Url::parse(target)
            .map_err(|e| Error::invalid_target(target, format!("Invalid URL: {}", e)))?;

        let host = url
            .host_str()
            .ok_or_else(|| Error::invalid_target(target, "No host in URL"))?
            .to_string();

        let port = url.port();
        Ok((host, port))
    } else if let Some(pos) = target.rfind(':') {
        // host:port format
        let host = target[..pos].to_string();
        let port_str = &target[pos + 1..];
        let port = port_str
            .parse::<u16>()
            .map_err(|_| Error::invalid_target(target, "Invalid port number"))?;
        Ok((host, Some(port)))
    } else {
        // Just host
        Ok((target.to_string(), None))
    }
}

/// Parse CIDR notation into list of IP addresses
pub fn parse_cidr(cidr: &str) -> Result<Vec<IpAddr>> {
    use ipnetwork::IpNetwork;

    let network = cidr
        .parse::<IpNetwork>()
        .map_err(|e| Error::Parse(format!("Invalid CIDR: {}", e)))?;

    Ok(network.iter().collect())
}

/// Parse port range (e.g., "80-443" or "8000-9000")
pub fn parse_port_range(range: &str) -> Result<Vec<u16>> {
    if let Some(pos) = range.find('-') {
        let start = range[..pos]
            .parse::<u16>()
            .map_err(|_| Error::Parse(format!("Invalid port: {}", &range[..pos])))?;
        let end = range[pos + 1..]
            .parse::<u16>()
            .map_err(|_| Error::Parse(format!("Invalid port: {}", &range[pos + 1..])))?;

        if start > end {
            return Err(Error::Parse(format!(
                "Invalid port range: {} > {}",
                start, end
            )));
        }

        Ok((start..=end).collect())
    } else {
        // Single port
        let port = range
            .parse::<u16>()
            .map_err(|_| Error::Parse(format!("Invalid port: {}", range)))?;
        Ok(vec![port])
    }
}

/// Parse duration string (e.g., "30s", "5m", "1h")
pub fn parse_duration(duration: &str) -> Result<std::time::Duration> {
    let duration = duration.trim();

    if duration.is_empty() {
        return Err(Error::Parse("Empty duration".to_string()));
    }

    let (value_str, unit) = if duration.ends_with("ms") {
        (&duration[..duration.len() - 2], "ms")
    } else if duration.ends_with('s') {
        (&duration[..duration.len() - 1], "s")
    } else if duration.ends_with('m') {
        (&duration[..duration.len() - 1], "m")
    } else if duration.ends_with('h') {
        (&duration[..duration.len() - 1], "h")
    } else {
        (duration, "s") // Default to seconds
    };

    let value: u64 = value_str
        .parse()
        .map_err(|_| Error::Parse(format!("Invalid duration value: {}", value_str)))?;

    Ok(match unit {
        "ms" => std::time::Duration::from_millis(value),
        "s" => std::time::Duration::from_secs(value),
        "m" => std::time::Duration::from_secs(value * 60),
        "h" => std::time::Duration::from_secs(value * 3600),
        _ => std::time::Duration::from_secs(value),
    })
}

/// Extract domain from URL or hostname
pub fn extract_domain(input: &str) -> String {
    if let Ok(url) = url::Url::parse(input) {
        if let Some(host) = url.host_str() {
            return host.to_string();
        }
    }

    // Remove port if present
    if let Some(pos) = input.rfind(':') {
        if let Ok(_) = input[pos + 1..].parse::<u16>() {
            return input[..pos].to_string();
        }
    }

    input.to_string()
}

/// Validate domain name
pub fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }

    // Check if it's an IP address
    if IpAddr::from_str(domain).is_ok() {
        return true;
    }

    // Basic domain validation
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() < 2 {
        return false;
    }

    for part in parts {
        if part.is_empty() || part.len() > 63 {
            return false;
        }

        if !part.chars().all(|c| c.is_alphanumeric() || c == '-') {
            return false;
        }

        if part.starts_with('-') || part.ends_with('-') {
            return false;
        }
    }

    true
}

/// Format bytes as human-readable string
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    format!("{:.2} {}", size, UNITS[unit_index])
}

/// Format duration as human-readable string
pub fn format_duration(duration: std::time::Duration) -> String {
    let secs = duration.as_secs();

    if secs < 60 {
        format!("{:.2}s", duration.as_secs_f64())
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    }
}

/// Sanitize string for safe output
pub fn sanitize_output(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_ascii() && !c.is_control())
        .collect()
}

/// Mask sensitive data for logging
pub fn mask_sensitive(input: &str) -> String {
    if input.len() <= 8 {
        return "*".repeat(input.len());
    }

    format!("{}...{}", &input[..4], &input[input.len() - 4..])
}

/// Return the top N most common ports based on curated frequency data
pub fn top_ports(count: u16) -> Vec<u16> {
    const TOP_PORTS: [u16; 30] = [
        80, 443, 8080, 8443, 8000, 22, 21, 25, 110, 995, 143, 993, 53, 3389, 5900, 3306, 5432,
        27017, 6379, 9200, 15672, 27018, 5000, 8081, 4443, 139, 445, 7001, 11211, 50070,
    ];

    if count == 0 {
        return Vec::new();
    }

    let take = usize::min(count as usize, TOP_PORTS.len());
    let mut ports = TOP_PORTS[..take].to_vec();
    ports.sort_unstable();
    ports.dedup();
    ports
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_target() {
        let (host, port) = parse_target("example.com:443").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, Some(443));

        let (host, port) = parse_target("example.com").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, None);

        let (host, port) = parse_target("https://example.com:8443/path").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, Some(8443));
    }

    #[test]
    fn test_parse_port_range() {
        let ports = parse_port_range("80-83").unwrap();
        assert_eq!(ports, vec![80, 81, 82, 83]);

        let ports = parse_port_range("443").unwrap();
        assert_eq!(ports, vec![443]);
    }

    #[test]
    fn test_parse_duration() {
        assert_eq!(
            parse_duration("30s").unwrap(),
            std::time::Duration::from_secs(30)
        );
        assert_eq!(
            parse_duration("5m").unwrap(),
            std::time::Duration::from_secs(300)
        );
        assert_eq!(
            parse_duration("1h").unwrap(),
            std::time::Duration::from_secs(3600)
        );
        assert_eq!(
            parse_duration("500ms").unwrap(),
            std::time::Duration::from_millis(500)
        );
    }

    #[test]
    fn test_extract_domain() {
        assert_eq!(
            extract_domain("https://example.com:443/path"),
            "example.com"
        );
        assert_eq!(extract_domain("example.com:8080"), "example.com");
        assert_eq!(extract_domain("example.com"), "example.com");
    }

    #[test]
    fn test_is_valid_domain() {
        assert!(is_valid_domain("example.com"));
        assert!(is_valid_domain("sub.example.com"));
        assert!(is_valid_domain("192.168.1.1"));
        assert!(!is_valid_domain("invalid..com"));
        assert!(!is_valid_domain("-invalid.com"));
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(512), "512.00 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1_048_576), "1.00 MB");
    }

    #[test]
    fn test_mask_sensitive() {
        assert_eq!(mask_sensitive("supersecret12345"), "supe...2345");
        assert_eq!(mask_sensitive("short"), "*****");
    }
}
