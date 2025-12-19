use serde::Deserialize;

#[derive(Debug, Deserialize, Default)]
pub struct Config {
    pub bind: Option<String>,
    pub whitelist: Option<Vec<String>>,
}

impl Config {
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let s = std::fs::read_to_string(path)?;
        let cfg: Self = toml::from_str(&s)?;
        Ok(cfg)
    }
}
