use figment::{Figment, providers::{Env, Toml, Format}};
use figment_cliarg_provider::FigmentCliArgsProvider;
use serde::{Deserialize, Deserializer};
use tracing::Level;

use std::env;

#[derive(Deserialize, Clone)]
pub struct LdapConnectionConfig {
    pub connection_url: String,
    pub bind_dn: String,
    pub bind_password: String,
    pub user_base_dn: String,
    pub group_base_dn: String,
    pub user_search_filter: String,
    pub group_search_filter: String,
    pub admin_filter: String,

    #[serde(default = "default_login_attribute")]
    pub login_attribute: String,
    #[serde(default = "default_display_name_attribute")]
    pub display_name_attribute: String,
}

fn default_login_attribute() -> String {
    "mail".to_string()
}

fn default_display_name_attribute() -> String {
    "displayName".to_string()
}

#[derive(Deserialize, Clone)]
pub struct FilesystemDriverConfig {
    pub path: String,
}

#[derive(Deserialize, Clone)]
#[serde(tag = "driver", rename_all = "snake_case")]
pub enum StorageConfig {
    Filesystem(FilesystemDriverConfig),
}

#[derive(Deserialize, Clone)]
pub struct SqliteDbConfig {
    pub path: String,
}

#[derive(Deserialize, Clone)]
pub struct TlsConfig {
    pub enable: bool,
    pub key: String,
    pub cert: String,
}

#[derive(Deserialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DatabaseConfig {
    Sqlite(SqliteDbConfig),
}

#[derive(Deserialize, Clone, Default)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    Human,
    #[default]
    Json,
}

#[derive(Deserialize, Clone, Default)]
#[serde(rename_all = "snake_case")]
pub enum RollPeriod {
    Minutely,
    Hourly,
    #[default]
    Daily,
    Never,
}

#[derive(Deserialize, Clone)]
pub struct LogConfig {
    /// The minimum level of logging
    #[serde(deserialize_with = "serialize_log_level", default = "default_log_level")]
    pub level: Level,
    /// The path of the logging file
    #[serde(default = "default_log_path")]
    pub path: String,
    /// The format of the produced logs
    #[serde(default)]
    pub format: LogFormat,
    /// The roll period of the file
    #[serde(default)]
    pub roll_period: RollPeriod,
    #[serde(default)]
    pub extra_logging: bool,
    pub env_filter: Option<String>,
}

#[derive(Deserialize, Clone)]
pub struct Config {
    pub listen_address: String,
    pub listen_port: String,
    url: Option<String>,
    #[serde(default)]
    pub extra_logging: bool,
    pub log: LogConfig,
    pub ldap: Option<LdapConnectionConfig>,
    pub database: DatabaseConfig,
    pub storage: StorageConfig,
    pub tls: Option<TlsConfig>,
    #[serde(skip)]
    pub jwt_key: String,
}

#[allow(dead_code)]
impl Config {
    pub fn new() -> Result<Self, figment::Error> {
        // The path of the config file without the file extension
        let path = {
            let args: Vec<String> = wild::args().collect();
            let (_args, argv) = argmap::parse(args.iter());

            match argv.get("--config-path") {
                Some(path) => { 
                    path.first().unwrap().clone()
                },
                None => match env::var("ORCA_REG_CONFIG") {
                    Ok(path) => path,
                    Err(_) => "config.toml".to_string(),
                }
            }
        };

        // Merge the config files
        let figment = Figment::new()
            .join(FigmentCliArgsProvider::new())
            .join(Env::prefixed("ORCA_REG_"))
            .join(Toml::file(format!("{}", path)));

        let mut config: Config = figment.extract()?;
        if let Some(url) = config.url.as_mut() {
            if url.ends_with("/") {
                *url = url[..url.len() - 1].to_string();
            }
        }
        
        Ok(config)
    }

    pub fn url(&self) -> String {
        match &self.url {
            Some(u) => u.clone(),
            None => format!("http://{}:{}", self.listen_address, self.listen_port)
        }
    }
}

fn default_log_level() -> Level {
    Level::INFO
}

fn default_log_path() -> String {
    "orca.log".to_string()
}

fn serialize_log_level<'de, D>(deserializer: D) -> Result<Level, D::Error>
where D: Deserializer<'de> {
    let s = String::deserialize(deserializer)?.to_lowercase();
    let s = s.as_str();
    
    match s {
        "error" => Ok(Level::ERROR),
        "warn" => Ok(Level::WARN),
        "info" => Ok(Level::INFO),
        "debug" => Ok(Level::DEBUG),
        "trace" => Ok(Level::TRACE),
        _ => Err(serde::de::Error::custom(format!("Unknown log level: '{}'", s))),
    }
}

/* fn<'de, D> serialize_log_level(D) -> Result<Level, D::Error>
where D: Deserializer<'de>
{

} */
//fn serialize_log_level() -> Level