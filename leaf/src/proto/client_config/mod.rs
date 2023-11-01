mod client_config;

use rand::seq::SliceRandom;
use super::server_config;
pub use client_config::*;



impl ProxyNode {
    fn is_match(&self, addr: &str, port: u16) -> bool {
        let port = port as u32;
        (self.get_server_domain().eq(addr) || self.get_server_address().eq(addr))
            && (self.get_server_port().eq(&port))
    }
}

#[cfg(test)]
mod client_config_test {
    use crate::proto::client_config::ProxyNode;
    use super::*;

    #[test]
    pub fn test_json_config() {
        let point = ProxyNode::default();
        let serialized = serde_json::to_string(&point).unwrap();

        println!("serialized = {}", serialized);

        let deserialized: ProxyNode = serde_json::from_str(&serialized).unwrap();

        println!("deserialized = {:?}", deserialized);

        assert_eq!(deserialized, point);
    }
}
