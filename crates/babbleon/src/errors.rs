use thiserror::Error;

pub type Result<T> = std::result::Result<T, BabbleonError>;

#[derive(Debug, Error)]
pub enum BabbleonError {
    #[error("vault error: {0}")]
    Vault(String),

    #[error("wrong passphrase")]
    WrongPassphrase,

    #[error("vault not found at {0}")]
    VaultNotFound(String),

    #[error("hardware unavailable: {0}")]
    HardwareUnavailable(String),

    #[error("mapping error: {0}")]
    Mapping(String),

    #[error("enforcement error: {0}")]
    Enforcement(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serde json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("toml decode error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("age encryption error: {0}")]
    AgeEncrypt(String),

    #[error("age decryption error: {0}")]
    AgeDecrypt(String),
}
