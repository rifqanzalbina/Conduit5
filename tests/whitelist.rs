use conduit5::whitelist::Whitelist;
use std::net::IpAddr;

#[test]
fn test_whitelist_parsing_and_matching() {
    let list = vec![
        "example.com".into(),
        "*.allowed.com".into(),
        "192.168.1.1".into(),
        "10.0.0.0/8".into(),
    ];
    let w = Whitelist::from_strings(list);

    assert!(w.allows_domain("example.com"));
    assert!(w.allows_domain("sub.allowed.com"));
    assert!(w.allows_domain("allowed.com")); // suffix match should allow

    let ip: IpAddr = "192.168.1.1".parse().unwrap();
    assert!(w.allows_ip(&ip));

    let ip2: IpAddr = "10.5.6.7".parse().unwrap();
    assert!(w.allows_ip(&ip2));

    let ip3: IpAddr = "8.8.8.8".parse().unwrap();
    assert!(!w.allows_ip(&ip3));
}
