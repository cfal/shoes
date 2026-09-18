/// Test to verify DNS resolution works
#[tokio::test]
async fn test_lookup_host_localhost() {
    let result = tokio::net::lookup_host(("localhost", 1234)).await;
    assert!(result.is_ok(), "lookup_host failed: {:?}", result.err());
    let addrs: Vec<_> = result.unwrap().collect();
    eprintln!("Resolved addresses for localhost: {:?}", addrs);
    assert!(!addrs.is_empty(), "Should resolve to at least one address");
}

#[tokio::test]
async fn test_lookup_host_127() {
    let result = tokio::net::lookup_host(("127.0.0.1", 1234)).await;
    assert!(result.is_ok(), "lookup_host failed: {:?}", result.err());
    let addrs: Vec<_> = result.unwrap().collect();
    eprintln!("Resolved addresses for 127.0.0.1: {:?}", addrs);
    assert!(!addrs.is_empty(), "Should resolve to at least one address");
}
