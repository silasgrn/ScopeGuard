use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ScopeService {
    pub name: String,
    pub protocol: String,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub exposed: bool,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ScopeFile {
    pub services: Vec<ScopeService>,
}

impl ScopeFile {
    pub fn load(path: &str) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|err| format!("Failed to read scope file '{}': {}", path, err))?;
        serde_json::from_str(&content)
            .map_err(|err| format!("Invalid JSON scope file '{}': {}", path, err))
    }
}
