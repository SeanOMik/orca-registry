use anyhow::anyhow;
use serde::{Deserialize, Serialize};

use std::fmt;

#[derive(Default, Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScopeType {
    #[default]
    Unknown,
    #[serde(rename = "repository")]
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

#[derive(Default, Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Action {
    #[default]
    None,
    #[serde(rename = "push")]
    Push,
    #[serde(rename = "pull")]
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

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Scope {
    #[serde(rename = "type")]
    pub scope_type: ScopeType,
    pub name: String,
    pub actions: Vec<Action>,
}

impl Scope {
    pub fn new(scope_type: ScopeType, path: String, actions: &[Action]) -> Self {
        Self {
            scope_type,
            name: path,
            actions: actions.to_vec(),
        }
    }

    pub fn to_error_details(&self) -> Vec<ScopeDetail> {
        let mut details = vec![];

        for action in &self.actions {
            details.push(ScopeDetail {
                scope_type: self.scope_type,
                name: self.name.clone(),
                action: *action,
            })
        }

        details
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let actions = self.actions
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<String>>()
            .join(",");

        write!(f, "{}:{}:{}", self.scope_type, self.name, actions)
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
                name: String::from(path),
                actions
            })
        } else {
            Err(anyhow!("Malformed scope string!"))
            //Err(serde::de::Error::custom("Malformed scope string!"))
        }
    }
}


#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScopeDetail {
    #[serde(rename = "type")]
    pub scope_type: ScopeType,
    pub name: String,
    pub action: Action,
}