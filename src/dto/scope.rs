use anyhow::anyhow;
use serde::{Deserialize, de::Visitor};

use std::fmt;

#[derive(Default, Debug)]
pub enum ScopeType {
    #[default]
    Unknown,
    Repository,
}

impl fmt::Display for ScopeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            ScopeType::Unknown => write!(f, ""),
            ScopeType::Repository => write!(f, "repository"),
        }
    }
}

#[derive(Default, Debug, Clone)]
pub enum Action {
    #[default]
    None,
    Push,
    Pull,
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Action::None => write!(f, ""),
            Action::Push => write!(f, "push"),
            Action::Pull => write!(f, "pull"),
        }
    }
}

#[derive(Default, Debug)]
pub struct Scope {
    scope_type: ScopeType,
    path: String,
    actions: Vec<Action>,
}

impl Scope {
    pub fn new(scope_type: ScopeType, path: String, actions: &[Action]) -> Self {
        Self {
            scope_type,
            path,
            actions: actions.to_vec(),
        }
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let actions = self.actions
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<String>>()
            .join(",");

        write!(f, "{}:{}:{}", self.scope_type, self.path, actions)
    }
}

impl TryFrom<&str> for Scope {
    type Error = anyhow::Error;

    fn try_from(val: &str) -> Result<Self, Self::Error> {
        let splits: Vec<&str> = val.split(":").collect();
        if splits.len() == 3 {
            let scope_type = match splits[0] {
                "repository" => ScopeType::Repository,
                _ => {
                    return Err(anyhow!("Invalid scope type: `{}`!", splits[0]));
                    //return Err(serde::de::Error::custom(format!("Invalid scope type: `{}`!", splits[0])));
                }
            };

            let path = splits[1];

            let actions: Result<Vec<Action>, anyhow::Error> = splits[2]
                .split(",")
                .map(|a| match a {
                    "pull" => Ok(Action::Pull),
                    "push" => Ok(Action::Push),
                    _ => Err(anyhow!("Invalid action: `{}`!", a)), //Err(serde::de::Error::custom(format!("Invalid action: `{}`!", a))),
                }).collect();
            let actions = actions?;

            Ok(Scope {
                scope_type,
                path: String::from(path),
                actions
            })
        } else {
            Err(anyhow!("Malformed scope string!"))
            //Err(serde::de::Error::custom("Malformed scope string!"))
        }
    }
}

pub struct ScopeVisitor {
    
}

impl<'de> Visitor<'de> for ScopeVisitor {
    type Value = Scope;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a Scope in the format of `repository:samalba/my-app:pull,push`.")
    }

    fn visit_str<E>(self, val: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error {
        println!("Start of visit_str!");
        
        let res = match Scope::try_from(val) {
            Ok(val) => Ok(val),
            Err(e) => Err(serde::de::Error::custom(format!("{}", e)))
        };

        res

        

        /* let splits: Vec<&str> = val.split(":").collect();
        if splits.len() == 3 {
            let scope_type = match splits[0] {
                "repository" => ScopeType::Repository,
                _ => {
                    return Err(serde::de::Error::custom(format!("Invalid scope type: `{}`!", splits[0])));
                }
            };

            let path = splits[1];

            let actions: Result<Vec<Action>, E> = splits[2]
                .split(",")
                .map(|a| match a {
                    "pull" => Ok(Action::Pull),
                    "push" => Ok(Action::Push),
                    _ => Err(serde::de::Error::custom(format!("Invalid action: `{}`!", a))),
                }).collect();
            let actions = actions?;

            Ok(Scope {
                scope_type,
                path: String::from(path),
                actions
            })
        } else {
            Err(serde::de::Error::custom("Malformed scope string!"))
        } */
    }
}

impl<'de> Deserialize<'de> for Scope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de> {
        deserializer.deserialize_str(ScopeVisitor {})
    }
}