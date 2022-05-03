mod common;

// app(socks) -> (socks)client(chain(ws+trojan)->chain(ws+trojan)) -> (chain(ws+trojan))server1(direct) -> (chain(ws+trojan))server2(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-ws",
    feature = "outbound-trojan",
    feature = "inbound-ws",
    feature = "inbound-trojan",
    feature = "outbound-direct",
    feature = "inbound-chain",
    feature = "outbound-chain",
))]
#[test]
fn test_out_chain_1() {
    let config1 = r#"
    {
        "inbounds": [
            {
                "protocol": "socks",
                "address": "127.0.0.1",
                "port": 1086
            }
        ],
        "outbounds": [
            {
                "protocol": "chain",
                "tag": "chain-server1-server2",
                "settings": {
                    "actors": [
                        "server1",
                        "server2"
                    ]
                }
            },
            {
                "protocol": "chain",
                "tag": "server1",
                "settings": {
                    "actors": [
                        "server1-ws",
                        "server1-trojan"
                    ]
                }
            },
            {
                "protocol": "ws",
                "tag": "server1-ws",
                "settings": {
                    "path": "/leaf"
                }
            },
            {
                "protocol": "trojan",
                "tag": "server1-trojan",
                "settings": {
                    "address": "127.0.0.1",
                    "port": 3001,
                    "password": "password"
                }
            },
            {
                "protocol": "chain",
                "tag": "server2",
                "settings": {
                    "actors": [
                        "server2-ws",
                        "server2-trojan"
                    ]
                }
            },
            {
                "protocol": "ws",
                "tag": "server2-ws",
                "settings": {
                    "path": "/leaf2"
                }
            },
            {
                "protocol": "trojan",
                "tag": "server2-trojan",
                "settings": {
                    "address": "127.0.0.1",
                    "port": 3002,
                    "password": "password"
                }
            }
        ]
    }
    "#;

    let config2 = r#"
    {
        "inbounds": [
            {
                "protocol": "chain",
                "tag": "server1",
                "address": "127.0.0.1",
                "port": 3001,
                "settings": {
                    "actors": [
                        "ws",
                        "trojan"
                    ]
                }
            },
            {
                "protocol": "ws",
                "tag": "ws",
                "settings": {
                    "path": "/leaf"
                }
            },
            {
                "protocol": "trojan",
                "tag": "trojan",
                "settings": {
                    "passwords": [
                        "password"
                    ]
                }
            }
        ],
        "outbounds": [
            {
                "protocol": "direct"
            }
        ]
    }
    "#;

    let config3 = r#"
    {
        "inbounds": [
            {
                "protocol": "chain",
                "tag": "server2",
                "address": "127.0.0.1",
                "port": 3002,
                "settings": {
                    "actors": [
                        "ws",
                        "trojan"
                    ]
                }
            },
            {
                "protocol": "ws",
                "tag": "ws",
                "settings": {
                    "path": "/leaf2"
                }
            },
            {
                "protocol": "trojan",
                "tag": "trojan",
                "settings": {
                    "passwords": [
                        "password"
                    ]
                }
            }
        ],
        "outbounds": [
            {
                "protocol": "direct"
            }
        ]
    }
    "#;

    let configs = vec![
        config1.to_string(),
        config2.to_string(),
        config3.to_string(),
    ];
    common::test_configs(configs, "127.0.0.1", 1086);
}
