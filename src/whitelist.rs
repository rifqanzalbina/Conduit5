use ipnet::IpNet;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub enum Entry {
    DomainSuffix(String),
    Ip(IpAddr),
    Cidr(IpNet),
}

#[derive(Debug, Clone)]
pub struct Whitelist {
    entries: Vec<Entry>,
}

impl Whitelist {
    pub fn from_strings(values: Vec<String>) -> Self {
        let mut entries = Vec::new();
        for v in values.into_iter() {
            let v = v.trim().to_lowercase();
            if v.contains('/') {
                if let Ok(c) = v.parse::<IpNet>() {
                    entries.push(Entry::Cidr(c));
                    continue;
                }
            }
            if let Ok(ip) = v.parse::<IpAddr>() {
                entries.push(Entry::Ip(ip));
                continue;
            }
            // domain suffix
            let s = if v.starts_with("*.") { v[2..].to_string() } else { v };
            entries.push(Entry::DomainSuffix(s));
        }
        Self { entries }
    }

    pub fn allows_domain(&self, domain: &str) -> bool {
        let d = domain.to_lowercase();
        for e in &self.entries {
            match e {
                Entry::DomainSuffix(suffix) => {
                    if d == *suffix || d.ends_with(&format!(".{}", suffix)) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }

    pub fn allows_ip(&self, ip: &IpAddr) -> bool {
        for e in &self.entries {
            match e {
                Entry::Ip(v) => {
                    if v == ip {
                        return true;
                    }
                }
                Entry::Cidr(net) => {
                    if net.contains(ip) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }

    pub fn allows_any_ip(&self, ips: &[IpAddr]) -> bool {
        ips.iter().any(|ip| self.allows_ip(ip))
    }
}
