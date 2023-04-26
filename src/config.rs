use figment::{Figment, providers::{Env, Toml, Format}};
use figment_cliarg_provider::FigmentCliArgsProvider;
use serde::Deserialize;

use std::env;

#[derive(Deserialize)]
pub struct Config {
    pub listen_address: String,
    pub listen_port: String,
    pub url: String,
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

        if config.url.ends_with("/") {
            config.url = config.url[..config.url.len() - 1].to_string();
        }
        
        Ok(config)
    }
}