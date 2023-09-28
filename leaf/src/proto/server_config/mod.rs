// @generated
mod server_config;
pub use server_config::*;

impl ServerConfig {
    pub fn build(
        client_platform_type: String,
        client_platform_version: String,
        client_platform_category: String,
        pk: Vec<u8>,
        random_content: Vec<u8>,
    ) -> ServerConfig {
        let mut server_config = ServerConfig::new();
        server_config.set_pubkey(pk);
        server_config.set_enc_method(EncMethodEnum::SM4_GCM);
        server_config.set_client_platform_type(client_platform_type);
        server_config.set_client_platform_version(client_platform_version);
        server_config.set_client_platform_category(client_platform_category);
        server_config.set_random_content(random_content);
        server_config
    }
}

impl EncMethodEnum {
    pub fn get_enum_from_string(name: &str) -> Option<EncMethodEnum> {
        match name {
            "aes-256-gcm" => Some(EncMethodEnum::AES_256_GCM),
            "aes-128-gcm" => Some(EncMethodEnum::AES_128_GCM),
            "chacha20-ietf-poly1305" => Some(EncMethodEnum::CHACHA20_IETF_POLY1305),
            "xchacha20-ietf-poly1305" => Some(EncMethodEnum::XCHACHA20_IETF_POLY1305),
            "sm4-gcm" => Some(EncMethodEnum::SM4_GCM),
            _ => None,
        }
    }
}
