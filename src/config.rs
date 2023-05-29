use figment::{Figment, providers::{Env, Toml, Format}};
use figment_cliarg_provider::FigmentCliArgsProvider;
use serde::Deserialize;

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
pub struct Config {
    pub listen_address: String,
    pub listen_port: String,
    pub url: Option<String>,
    pub ldap: Option<LdapConnectionConfig>,
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

    pub fn get_url(&self) -> String {
        match &self.url {
            Some(u) => u.clone(),
            None => format!("http://{}:{}", self.listen_address, self.listen_port)
        }
    }
}